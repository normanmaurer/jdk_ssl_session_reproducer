import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

public final class JDKSSLSessionReproducer {

    public static void main(String[] args) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(JDKSSLSessionReproducer.class.getResourceAsStream("test.p12"), "test".toCharArray());
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "test".toCharArray());
        SSLContext serverCtx = SSLContext.getInstance("TLS");
        serverCtx.init(kmf.getKeyManagers(), null, null);
        SSLEngine serverEngine = serverCtx.createSSLEngine();
        serverEngine.setUseClientMode(false);

        SSLContext clientCtx = SSLContext.getInstance("TLS");
        clientCtx.init(null, new TrustManager[] {
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) {
                        // NOOP
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) {
                        // NOOP
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
        }, null);


        SSLEngine clientEngine = clientCtx.createSSLEngine();

        clientEngine.setUseClientMode(true);

        handshake(clientEngine, serverEngine);
        SSLSession session = clientEngine.getSession();
        if (session.getValueNames().length != 0) {
            throw new AssertionError("Should be empty");
        }

        session.putValue("name", "value");
        if (session.getValueNames().length != 1) {
            throw new AssertionError("Shouldn't be empty");
        }

        SSLEngine clientEngine2 = clientCtx.createSSLEngine();

        SSLSession session2 = clientEngine2.getSession();
        if (session2.getValueNames().length != 0) {
            throw new AssertionError("Should be empty");
        }

        session2.putValue("name", "value");
        if (session2.getValueNames().length != 1) {
            throw new AssertionError("Shouldn't be empty");
        }

        SSLEngine clientEngine3 = clientCtx.createSSLEngine();
        SSLSession session3 = clientEngine3.getSession();
        if (session3.getValueNames().length != 0) {
            throw new AssertionError("Should be empty");
        }
    }

    private static void handshake(SSLEngine clientEngine, SSLEngine serverEngine) throws SSLException{
        ByteBuffer cTOs = ByteBuffer.allocate(clientEngine.getSession().getPacketBufferSize());
        ByteBuffer sTOc = ByteBuffer.allocate(serverEngine.getSession().getPacketBufferSize());

        ByteBuffer serverAppReadBuffer = ByteBuffer.allocate(
                serverEngine.getSession().getApplicationBufferSize());
        ByteBuffer clientAppReadBuffer = ByteBuffer.allocate(
                clientEngine.getSession().getApplicationBufferSize());

        clientEngine.beginHandshake();
        serverEngine.beginHandshake();

        ByteBuffer empty = ByteBuffer.allocate(0);

        SSLEngineResult clientResult;
        SSLEngineResult serverResult;

        boolean clientHandshakeFinished = false;
        boolean serverHandshakeFinished = false;

        do {
            if (!clientHandshakeFinished) {
                clientResult = clientEngine.wrap(empty, cTOs);
                runDelegatedTasks(clientResult, clientEngine);

                if (isHandshakeFinished(clientResult)) {
                    clientHandshakeFinished = true;
                }
            }

            if (!serverHandshakeFinished) {
                serverResult = serverEngine.wrap(empty, sTOc);
                runDelegatedTasks(serverResult, serverEngine);

                if (isHandshakeFinished(serverResult)) {
                    serverHandshakeFinished = true;
                }
            }

            cTOs.flip();
            sTOc.flip();

            if (!clientHandshakeFinished) {
                clientResult = clientEngine.unwrap(sTOc, clientAppReadBuffer);

                runDelegatedTasks(clientResult, clientEngine);

                if (isHandshakeFinished(clientResult)) {
                    clientHandshakeFinished = true;
                }
            }

            if (!serverHandshakeFinished) {
                serverResult = serverEngine.unwrap(cTOs, serverAppReadBuffer);
                runDelegatedTasks(serverResult, serverEngine);

                if (isHandshakeFinished(serverResult)) {
                    serverHandshakeFinished = true;
                }
            }

            sTOc.compact();
            cTOs.compact();
        } while (!clientHandshakeFinished || !serverHandshakeFinished);
    }

    private static boolean isHandshakeFinished(SSLEngineResult result) {
        return result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED;
    }

    private static void runDelegatedTasks(SSLEngineResult result, SSLEngine engine) {
        if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            for (;;) {
                Runnable task = engine.getDelegatedTask();
                if (task == null) {
                    break;
                }
                task.run();
            }
        }
    }
}
