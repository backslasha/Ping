package pinger;

public class StopWatch {
    private long startTime = 0;
    private long stopTime = 0;
    private boolean isRunning = false;

    public long start() {
        isRunning = true;
        startTime = System.currentTimeMillis();
        return startTime;
    }

    public long stop() {
        stopTime = System.currentTimeMillis();
        isRunning = false;
        if (stopTime - startTime < 0) {
            try {
                throw new Exception("StopWacth has not start yet!");
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
        return stopTime - startTime;
    }

    public long elapsed() {
        if (isRunning) {
            return System.currentTimeMillis() - startTime;
        } else {
            if (stopTime - startTime < 0) {
                try {
                    throw new Exception("StopWacth has not start yet!");
                } catch (Exception e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
            return stopTime - startTime;
        }
    }

    public boolean isRunning() {
        return isRunning;
    }
}
