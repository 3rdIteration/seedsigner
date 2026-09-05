// Launches one or more JavaCard applets inside jcardsim and serves APDUs over TCP.
//
// Why this exists rather than specter-javacard's bundled simulator.jar: that one calls
// jcardsim's two-argument installApplet(aid, class), which supplies no install
// parameters. Several of the applets we care about parse them in install() -- SeedKeeper
// reads OM_SIZE out of them and indexes into the array unconditionally -- so they throw
// SystemException before the simulator ever opens its port. This launcher builds the
// standard [aidLen][aid][ctrlLen][ctrl][dataLen][data] block and uses the five-argument
// form, the same way status-keycard's own JUnit tests do.
//
// The wire protocol is length-prefixed rather than raw: each frame is a 2-byte big-endian
// length followed by that many bytes. specter's raw-stream version reads one APDU per
// recv() with a 256-byte cap, which silently truncates anything larger (SeedKeeper secret
// exports, RSA reads) and makes it look like an applet bug.

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;

public class SimLauncher {

    private static final int MAX_FRAME = 65535;

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02X", x));
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        String s = hex.replace(" ", "").replace(":", "");
        if (s.length() % 2 != 0) {
            throw new IllegalArgumentException("odd-length hex: " + hex);
        }
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static class AppletSpec {
        final byte[] aid;
        final String className;
        final byte[] installBlock;

        AppletSpec(String spec) {
            // AID:class[:installBlockHex]
            //
            // The block is passed in whole rather than assembled here, because its shape
            // is applet-specific: SeedKeeper and Satochip parse the full GlobalPlatform
            // [aidLen][aid][ctrlLen][ctrl][dataLen][data], while Keycard's install()
            // expects only [aidLen][aid]. Building it in Python keeps that decision
            // somewhere legible instead of hidden in a Java helper.
            String[] parts = spec.split(":", 3);
            if (parts.length < 2) {
                throw new IllegalArgumentException(
                    "--applet wants AID:class[:installBlockHex], got " + spec);
            }
            this.aid = hexToBytes(parts[0]);
            this.className = parts[1];
            this.installBlock = parts.length == 3 ? hexToBytes(parts[2]) : new byte[0];
        }
    }

    public static void main(String[] args) throws Exception {
        int port = 0;
        String classesDir = null;
        List<AppletSpec> applets = new ArrayList<>();

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--port":    port = Integer.parseInt(args[++i]); break;
                case "--classes": classesDir = args[++i]; break;
                case "--applet":  applets.add(new AppletSpec(args[++i])); break;
                default: throw new IllegalArgumentException("unknown argument: " + args[i]);
            }
        }
        if (port == 0 || classesDir == null || applets.isEmpty()) {
            System.err.println("usage: SimLauncher --port N --classes CLASSPATH --applet AID:class[:paramsHex] ...");
            System.exit(2);
        }

        // The applet's own classes are loaded from the build output of its repo, so the
        // bytecode under test is exactly what would be converted into a CAP.
        //
        // This is a classpath, not one directory: Keycard's Crypto references
        // BigNumberMath from keycard-math.jar, a prebuilt JavaCard library that has no
        // sources in the repo, so the applet cannot be loaded without it alongside.
        String[] entries = classesDir.split(java.io.File.pathSeparator);
        URL[] urls = new URL[entries.length];
        for (int i = 0; i < entries.length; i++) {
            urls[i] = new File(entries[i]).toURI().toURL();
        }
        ClassLoader loader = new URLClassLoader(urls, SimLauncher.class.getClassLoader());

        CardSimulator simulator = new CardSimulator();
        AID firstAid = null;
        for (AppletSpec spec : applets) {
            AID aid = AIDUtil.create(spec.aid);
            Class<?> cls = loader.loadClass(spec.className);
            byte[] block = spec.installBlock;
            try {
                simulator.installApplet(aid, cls.asSubclass(javacard.framework.Applet.class),
                                        block, (short) 0, (byte) block.length);
            } catch (javacard.framework.CardRuntimeException e) {
                // The applet's install() rejected us. The reason code is the only useful
                // detail -- a bare SystemException says nothing about which resource or
                // algorithm jcardsim could not provide.
                System.err.println("install of " + spec.className + " failed: "
                                   + e.getClass().getName() + " reason=" + e.getReason());
                throw e;
            }
            if (firstAid == null) {
                firstAid = aid;
            }
        }
        simulator.selectApplet(firstAid);

        try (ServerSocket server = new ServerSocket(port)) {
            // Announce readiness on stdout so the Python side can wait for a line rather
            // than sleeping a fixed interval and hoping.
            System.out.println("READY " + port);
            System.out.flush();

            while (true) {
                try (Socket sock = server.accept()) {
                    System.err.println("accepted " + sock.getRemoteSocketAddress());
                    sock.setTcpNoDelay(true);
                    DataInputStream in = new DataInputStream(sock.getInputStream());
                    DataOutputStream out = new DataOutputStream(sock.getOutputStream());
                    serve(simulator, in, out);
                } catch (EOFException e) {
                    // client hung up; wait for the next one
                } catch (Throwable t) {
                    System.err.println("connection failed: " + t);
                    t.printStackTrace();
                }
            }
        }
    }

    private static void serve(CardSimulator simulator, DataInputStream in, DataOutputStream out)
            throws Exception {
        while (true) {
            int length;
            try {
                length = in.readUnsignedShort();
            } catch (EOFException e) {
                return;
            }
            if (length == 0 || length > MAX_FRAME) {
                return;
            }
            byte[] apdu = new byte[length];
            in.readFully(apdu);

            byte[] response;
            try {
                ResponseAPDU r = simulator.transmitCommand(new CommandAPDU(apdu));
                response = r.getBytes();
            } catch (Throwable t) {
                // Throwable, not Exception: applet code runs with -noverify, so a failure
                // inside it can surface as an Error (VerifyError, NoClassDefFoundError for
                // an unimplemented algorithm). Report it as 6F00 and keep the connection
                // up, so the Python side sees a status word like a real card would rather
                // than an opaque socket close.
                System.err.println("transmit failed for " + bytesToHex(apdu) + ": " + t);
                t.printStackTrace();
                response = new byte[] { (byte) 0x6F, (byte) 0x00 };
            }

            out.writeShort(response.length);
            out.write(response);
            out.flush();
        }
    }
}
