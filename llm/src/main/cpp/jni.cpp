// JNI bridge for the vendored llama.cpp build (Component 12, "Xairex").
//
// The full chat transcript is re-rendered with the model's own chat template on every
// generation; the KV cache is reused by rewinding the context memory to the longest
// common token prefix, so only the new turn is processed after the first reply.
// See notes/2026-10-19-1131-ai-assistant-design.md.

#include <jni.h>

#include <android/log.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "llama.h"

#define LOG_TAG "ecrew-llm"
#define LOG_INFO(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOG_WARN(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOG_ERROR(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {

constexpr int32_t PROMPT_CHUNK = 512;
constexpr int32_t CONTEXT_HEADROOM = 8;

struct Engine {
    llama_model * model = nullptr;
    llama_context * ctx = nullptr;
    const llama_vocab * vocab = nullptr;
    std::atomic<bool> stop{false};
    // Tokens currently resident in the context memory (positions are their indexes).
    std::vector<llama_token> memory_tokens;
};

void android_log_callback(enum ggml_log_level level, const char * text, void * /* user_data */) {
    if (level == GGML_LOG_LEVEL_ERROR) {
        LOG_ERROR("%s", text);
    } else if (level == GGML_LOG_LEVEL_WARN) {
        LOG_WARN("%s", text);
    }
}

void ensure_backend() {
    static std::once_flag once;
    std::call_once(once, []() {
        llama_log_set(android_log_callback, nullptr);
        llama_backend_init();
    });
}

bool is_valid_utf8(const std::string & value) {
    const size_t n = value.size();
    size_t i = 0;
    while (i < n) {
        const unsigned char c = static_cast<unsigned char>(value[i]);
        int extra = 0;
        if (c < 0x80) {
            extra = 0;
        } else if ((c & 0xE0) == 0xC0) {
            extra = 1;
        } else if ((c & 0xF0) == 0xE0) {
            extra = 2;
        } else if ((c & 0xF8) == 0xF0) {
            extra = 3;
        } else {
            return false;
        }
        if (i + static_cast<size_t>(extra) >= n) return false;
        for (int k = 1; k <= extra; ++k) {
            if ((static_cast<unsigned char>(value[i + k]) & 0xC0) != 0x80) return false;
        }
        i += static_cast<size_t>(extra) + 1;
    }
    return true;
}

/** Fixed-capacity batch views over caller-owned arrays (grows never reallocate). */
struct Batch {
    std::vector<llama_token> tokens;
    std::vector<llama_pos> pos;
    std::vector<int32_t> n_seq_id;
    std::vector<llama_seq_id> seq_ids;
    std::vector<llama_seq_id *> seq_id_ptrs;
    std::vector<int8_t> logits;
    llama_batch batch{};

    explicit Batch(size_t capacity) {
        tokens.resize(capacity);
        pos.resize(capacity);
        n_seq_id.resize(capacity);
        seq_ids.assign(capacity, 0);
        seq_id_ptrs.resize(capacity);
        logits.resize(capacity);
        for (size_t i = 0; i < capacity; ++i) seq_id_ptrs[i] = &seq_ids[i];
        batch.token = tokens.data();
        batch.embd = nullptr;
        batch.pos = pos.data();
        batch.n_seq_id = n_seq_id.data();
        batch.seq_id = seq_id_ptrs.data();
        batch.logits = logits.data();
        batch.n_tokens = 0;
    }
};

/**
 * Decodes tokens[from, to) with explicit positions. Returns 0 on success, 1 when a
 * stop was requested, -1 on decode failure.
 */
int decode_range(
        Engine * engine,
        Batch & batch,
        const std::vector<llama_token> & tokens,
        int32_t from,
        int32_t to,
        bool logits_at_end) {
    for (int32_t start = from; start < to; start += PROMPT_CHUNK) {
        const int32_t count = std::min(PROMPT_CHUNK, to - start);
        for (int32_t j = 0; j < count; ++j) {
            batch.tokens[j] = tokens[static_cast<size_t>(start + j)];
            batch.pos[j] = static_cast<llama_pos>(start + j);
            batch.n_seq_id[j] = 1;
            batch.logits[j] = (logits_at_end && start + j == to - 1) ? 1 : 0;
        }
        batch.batch.n_tokens = count;
        if (llama_decode(engine->ctx, batch.batch) != 0) return -1;
        if (engine->stop.load()) return 1;
    }
    return 0;
}

int decode_one(Engine * engine, Batch & batch, llama_token token, llama_pos position) {
    batch.tokens[0] = token;
    batch.pos[0] = position;
    batch.n_seq_id[0] = 1;
    batch.logits[0] = 1;
    batch.batch.n_tokens = 1;
    return llama_decode(engine->ctx, batch.batch);
}

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_ecrew_toolkit_ai_LlamaNative_nativeVersion(JNIEnv * env, jobject /* this */) {
    return env->NewStringUTF(llama_version());
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_ecrew_toolkit_ai_LlamaNative_nativeLoad(
        JNIEnv * env,
        jobject /* this */,
        jstring jmodel_path,
        jint jn_ctx,
        jint jn_threads) {
    ensure_backend();

    const char * path = env->GetStringUTFChars(jmodel_path, nullptr);
    if (path == nullptr) return 0;

    Engine * engine = new Engine();

    llama_model_params model_params = llama_model_default_params();
    model_params.n_gpu_layers = 0;
    engine->model = llama_model_load_from_file(path, model_params);
    env->ReleaseStringUTFChars(jmodel_path, path);
    if (engine->model == nullptr) {
        LOG_WARN("Model load failed");
        delete engine;
        return 0;
    }

    llama_context_params context_params = llama_context_default_params();
    context_params.n_ctx = static_cast<uint32_t>(jn_ctx);
    context_params.n_batch = PROMPT_CHUNK;
    context_params.n_ubatch = PROMPT_CHUNK;
    context_params.n_threads = jn_threads;
    context_params.n_threads_batch = jn_threads;
    engine->ctx = llama_init_from_model(engine->model, context_params);
    if (engine->ctx == nullptr) {
        LOG_WARN("Context creation failed");
        llama_model_free(engine->model);
        delete engine;
        return 0;
    }
    engine->vocab = llama_model_get_vocab(engine->model);
    LOG_INFO(
        "Model loaded: n_ctx=%u (trained %d), threads=%d, %s",
        llama_n_ctx(engine->ctx),
        llama_model_n_ctx_train(engine->model),
        jn_threads,
        llama_version());
    return reinterpret_cast<jlong>(engine);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_ecrew_toolkit_ai_LlamaNative_nativeGenerate(
        JNIEnv * env,
        jobject /* this */,
        jlong handle,
        jstring jsystem,
        jobjectArray jroles,
        jobjectArray jcontents,
        jint jmax_tokens,
        jfloat jtemperature,
        jfloat jtop_p,
        jint jtop_k,
        jlong jseed,
        jobject jcallback) {
    Engine * engine = reinterpret_cast<Engine *>(handle);
    if (engine == nullptr || engine->ctx == nullptr || jroles == nullptr ||
        jcontents == nullptr || jcallback == nullptr) {
        return -1;
    }

    const int32_t n_ctx = static_cast<int32_t>(llama_n_ctx(engine->ctx));
    if (n_ctx <= CONTEXT_HEADROOM) return -1;

    engine->stop.store(false);

    // ---- collect the chat messages ------------------------------------------------
    std::string system;
    if (jsystem != nullptr) {
        const char * value = env->GetStringUTFChars(jsystem, nullptr);
        if (value != nullptr) {
            system = value;
            env->ReleaseStringUTFChars(jsystem, value);
        }
    }

    const jsize n_msg = env->GetArrayLength(jroles);
    std::vector<std::string> roles(static_cast<size_t>(n_msg));
    std::vector<std::string> contents(static_cast<size_t>(n_msg));
    for (jsize i = 0; i < n_msg; ++i) {
        jstring jrole = static_cast<jstring>(env->GetObjectArrayElement(jroles, i));
        if (jrole != nullptr) {
            const char * role = env->GetStringUTFChars(jrole, nullptr);
            if (role != nullptr) {
                roles[static_cast<size_t>(i)] = role;
                env->ReleaseStringUTFChars(jrole, role);
            }
            env->DeleteLocalRef(jrole);
        }
        jbyteArray jbytes = static_cast<jbyteArray>(env->GetObjectArrayElement(jcontents, i));
        if (jbytes != nullptr) {
            const jsize length = env->GetArrayLength(jbytes);
            jbyte * bytes = env->GetByteArrayElements(jbytes, nullptr);
            if (bytes != nullptr) {
                contents[static_cast<size_t>(i)].assign(
                    reinterpret_cast<const char *>(bytes), static_cast<size_t>(length));
                env->ReleaseByteArrayElements(jbytes, bytes, JNI_ABORT);
            }
            env->DeleteLocalRef(jbytes);
        }
    }

    std::vector<llama_chat_message> messages;
    if (!system.empty()) {
        messages.push_back({"system", system.c_str()});
    }
    for (jsize i = 0; i < n_msg; ++i) {
        if (roles[static_cast<size_t>(i)].empty()) continue;
        messages.push_back({roles[static_cast<size_t>(i)].c_str(),
                            contents[static_cast<size_t>(i)].c_str()});
    }
    if (messages.empty()) return -1;

    // ---- render the prompt with the model's chat template -------------------------
    std::string prompt;
    const char * tmpl = llama_model_chat_template(engine->model, nullptr);
    if (tmpl != nullptr) {
        const int32_t needed = llama_chat_apply_template(
            tmpl, messages.data(), messages.size(), true, nullptr, 0);
        if (needed > 0) {
            std::vector<char> buffer(static_cast<size_t>(needed) + 1, '\0');
            const int32_t written = llama_chat_apply_template(
                tmpl, messages.data(), messages.size(), true,
                buffer.data(), static_cast<int32_t>(buffer.size()));
            if (written > 0) prompt.assign(buffer.data(), static_cast<size_t>(written));
        }
    }
    if (prompt.empty()) {
        // Fallback: the bundled model's native ChatML format.
        for (const llama_chat_message & message : messages) {
            prompt += "<|im_start|>";
            prompt += message.role;
            prompt += "\n";
            prompt += message.content;
            prompt += "<|im_end|>\n";
        }
        prompt += "<|im_start|>assistant\n";
    }

    // ---- tokenize ----------------------------------------------------------------
    std::vector<llama_token> tokens(static_cast<size_t>(n_ctx) + 16);
    int32_t count = llama_tokenize(
        engine->vocab, prompt.data(), static_cast<int32_t>(prompt.size()),
        tokens.data(), static_cast<int32_t>(tokens.size()), true, true);
    if (count < 0) {
        tokens.resize(static_cast<size_t>(-count) + 16);
        count = llama_tokenize(
            engine->vocab, prompt.data(), static_cast<int32_t>(prompt.size()),
            tokens.data(), static_cast<int32_t>(tokens.size()), true, true);
    }
    if (count <= 0) return -1;
    tokens.resize(static_cast<size_t>(count));

    const int32_t limit = n_ctx - CONTEXT_HEADROOM;
    if (count > limit) {
        LOG_WARN("Prompt too long (%d tokens); keeping the last %d", count, limit);
        tokens.erase(tokens.begin(), tokens.begin() + (count - limit));
    }

    // ---- rewind the memory to the longest common prefix ---------------------------
    size_t common = 0;
    while (common < engine->memory_tokens.size() && common < tokens.size() &&
           engine->memory_tokens[common] == tokens[common]) {
        ++common;
    }
    if (common == tokens.size()) {
        // Always re-decode the last token so the logits are fresh.
        common = tokens.size() - 1;
    }
    if (common < engine->memory_tokens.size()) {
        llama_memory_seq_rm(
            llama_get_memory(engine->ctx), 0, static_cast<llama_pos>(common), -1);
        engine->memory_tokens.resize(common);
    }
    if (engine->memory_tokens.empty()) {
        llama_memory_clear(llama_get_memory(engine->ctx), false);
    }

    Batch batch(static_cast<size_t>(n_ctx));
    const int decode_status = decode_range(
        engine, batch, tokens, static_cast<int32_t>(common),
        static_cast<int32_t>(tokens.size()), true);
    if (decode_status < 0) return -1;
    if (decode_status == 1) {
        llama_memory_clear(llama_get_memory(engine->ctx), false);
        engine->memory_tokens.clear();
        return 0;
    }
    engine->memory_tokens.insert(
        engine->memory_tokens.end(), tokens.begin() + common, tokens.end());

    // ---- sampling chain ------------------------------------------------------------
    llama_sampler * chain = llama_sampler_chain_init(llama_sampler_chain_default_params());
    if (chain == nullptr) return -1;
    llama_sampler_chain_add(chain, llama_sampler_init_penalties(
        llama_vocab_n_tokens(engine->vocab), 64, 1.1f, 0.0f, 0.0f));
    llama_sampler_chain_add(chain, llama_sampler_init_top_k(jtop_k));
    llama_sampler_chain_add(chain, llama_sampler_init_top_p(jtop_p, 1));
    llama_sampler_chain_add(chain, llama_sampler_init_temp(jtemperature));
    const uint32_t seed =
        jseed < 0 ? LLAMA_DEFAULT_SEED : static_cast<uint32_t>(jseed);
    llama_sampler_chain_add(chain, llama_sampler_init_dist(seed));

    jclass callback_class = env->GetObjectClass(jcallback);
    jmethodID on_token = env->GetMethodID(callback_class, "onToken", "([B)Z");
    env->DeleteLocalRef(callback_class);
    if (on_token == nullptr) {
        llama_sampler_free(chain);
        return -1;
    }

    // ---- generation loop ------------------------------------------------------------
    int32_t generated = 0;
    llama_pos position = static_cast<llama_pos>(engine->memory_tokens.size());
    std::string pending;

    for (int32_t i = 0; i < jmax_tokens; ++i) {
        if (engine->stop.load()) break;

        const llama_token token = llama_sampler_sample(chain, engine->ctx, -1);
        if (token < 0) break;
        llama_sampler_accept(chain, token);
        if (llama_vocab_is_eog(engine->vocab, token)) break;

        char small[256];
        int32_t piece = llama_token_to_piece(
            engine->vocab, token, small, static_cast<int32_t>(sizeof(small)), 0, false);
        if (piece < 0) {
            std::vector<char> large(static_cast<size_t>(-piece) + 8);
            piece = llama_token_to_piece(
                engine->vocab, token, large.data(),
                static_cast<int32_t>(large.size()), 0, false);
            if (piece > 0) pending.append(large.data(), static_cast<size_t>(piece));
        } else if (piece > 0) {
            pending.append(small, static_cast<size_t>(piece));
        }
        ++generated;

        if (!pending.empty() && is_valid_utf8(pending)) {
            jbyteArray data = env->NewByteArray(static_cast<jsize>(pending.size()));
            if (data == nullptr) break;
            env->SetByteArrayRegion(
                data, 0, static_cast<jsize>(pending.size()),
                reinterpret_cast<const jbyte *>(pending.data()));
            const jboolean keep = env->CallBooleanMethod(jcallback, on_token, data);
            env->DeleteLocalRef(data);
            pending.clear();
            if (env->ExceptionCheck()) {
                llama_sampler_free(chain);
                return -1;
            }
            if (keep == JNI_FALSE) break;
        }

        if (decode_one(engine, batch, token, position) != 0) {
            llama_sampler_free(chain);
            return -1;
        }
        ++position;
        engine->memory_tokens.push_back(token);
    }

    llama_sampler_free(chain);
    return generated;
}

extern "C" JNIEXPORT void JNICALL
Java_com_ecrew_toolkit_ai_LlamaNative_nativeStop(
        JNIEnv * /* env */, jobject /* this */, jlong handle) {
    Engine * engine = reinterpret_cast<Engine *>(handle);
    if (engine != nullptr) engine->stop.store(true);
}

extern "C" JNIEXPORT void JNICALL
Java_com_ecrew_toolkit_ai_LlamaNative_nativeFree(
        JNIEnv * /* env */, jobject /* this */, jlong handle) {
    Engine * engine = reinterpret_cast<Engine *>(handle);
    if (engine == nullptr) return;
    engine->stop.store(true);
    if (engine->ctx != nullptr) llama_free(engine->ctx);
    if (engine->model != nullptr) llama_model_free(engine->model);
    delete engine;
}
