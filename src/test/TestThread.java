package test;

public class TestThread {
    public static void main(String[] args) {
        Thread thread = new Thread() {
            public void run() {
                try {
                    while (true) {
                        Thread.sleep(500);
                        System.out.println(Thread.currentThread().getName() + " is running.");
                    }

                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                System.out.println(Thread.currentThread().getName() + " is over.");
            }

        };

        thread.start();
        System.out.println(Thread.currentThread().getName() + " is over.");
    }
}
