// Shizuku user service for the global HTTP proxy toggle. There is no arbitrary command
// method: only the four validated settings operations below are exposed.
package com.ecrew.toolkit.intercept;

interface IProxyShellService {
    void destroy() = 16777114;

    void exit() = 1;

    String getProxy() = 2;

    int setProxy(String host, int port) = 3;

    int clearProxy() = 4;

    int restoreProxy(String value) = 5;
}
