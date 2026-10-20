// Binder of the Shizuku crash-capture user service.
//
// The service has no caller-supplied command text: mode 0 reads the recent logcat buffer and
// modes 1/2 read one fixed dropbox crash tag. stdout is pulled in chunks below the binder limit.
package com.ecrew.toolkit.apk.fuzz;

interface IFuzzShellService {
    /** Reserved destroy transaction; Shizuku calls this to stop the service. */
    void destroy() = 16777114;

    void exit() = 1;

    /** 0 = crash logcat, 1 = data_app_crash, 2 = system_app_crash, 3 = main logcat. */
    int capture(int mode) = 2;

    int exitCode() = 3;

    String stderr() = 4;

    byte[] read(int offset, int length) = 5;
}
