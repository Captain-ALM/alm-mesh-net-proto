package test;

import com.captainalm.lib.mesh.crypto.IHasher;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Provides a hasher.
 *
 * @author Alfred Manville
 */
public class Hasher implements IHasher {
    final ThreadLocal<MessageDigest> lDigest = new ThreadLocal<>();

    @Override
    public byte[] hash(byte[] bytes) {
        if (bytes == null)
            return new byte[32];
        try {
            if (lDigest.get() == null)
                lDigest.set(MessageDigest.getInstance("SHA-256"));
            return lDigest.get().digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            return new byte[32];
        }
    }

    @Override
    public byte[] hashStream(InputStream inputStream, int i) throws IOException {
        if (inputStream == null)
            return new byte[32];
        try {
            if (lDigest.get() == null)
                lDigest.set(MessageDigest.getInstance("SHA-256"));
            byte[] buff = new byte[8192];
            int n = inputStream.read(buff, 0, Math.min(i, 8192));
            while (n > 0) {
                lDigest.get().update(buff, 0, n);
                i -= n;
                n = inputStream.read(buff, 0, Math.min(i, 8192));
            }
            return lDigest.get().digest();
        } catch (NoSuchAlgorithmException e) {
            return new byte[32];
        }
    }
}
