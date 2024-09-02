package burp.api.montoya.logging;

import java.io.PrintStream;

public class StubLogging implements Logging {
    public static final Logging LOGGING = new StubLogging();

    @Override
    public PrintStream output() {
        return null;
    }

    @Override
    public PrintStream error() {
        return null;
    }

    @Override
    public void logToOutput(String message) {
    }

    @Override
    public void logToError(String message) {
    }

    @Override
    public void logToError(String message, Throwable cause) {
    }

    @Override
    public void logToError(Throwable cause) {
    }

    @Override
    public void raiseDebugEvent(String message) {
    }

    @Override
    public void raiseInfoEvent(String message) {
    }

    @Override
    public void raiseErrorEvent(String message) {
    }

    @Override
    public void raiseCriticalEvent(String message) {
    }
}
