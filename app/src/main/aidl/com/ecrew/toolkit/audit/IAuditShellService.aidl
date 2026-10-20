// Binder of the Shizuku audit user service (design note 9c).
//
// Shizuku loads AuditUserService into an app_process running as the served user (shell on a
// production device started from a PC, root only if the operator started Shizuku as root).
// The app process pulls fixed read-only command output in chunks so no binder transaction
// approaches the 1 MB limit. No command text is ever derived from user input.
package com.ecrew.toolkit.audit;

interface IAuditShellService {
    /** Reserved destroy transaction; Shizuku calls this to stop the service. */
    void destroy() = 16777114;

    void exit() = 1;

    /**
     * Runs one command from the frozen table.
     * Returns the stdout byte count on success, or a negative error code:
     * -4 command outside the table, -5 timeout, -6 start failure, -7 stdout over the cap.
     */
    int execute(String command) = 2;

    /** The process exit code of the last successful [execute]. */
    int exitCode() = 3;

    /** Captured stderr of the last [execute], capped at 64 KiB. */
    String stderr() = 4;

    /** A chunk of the captured stdout; empty past the end. */
    byte[] read(int offset, int length) = 5;
}
