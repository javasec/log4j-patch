package org.javaweb.log4j;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.commons.AdviceAdapter;

import java.io.*;
import java.net.JarURLConnection;
import java.net.URL;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.zip.CRC32;
import java.util.zip.Deflater;

import static org.apache.commons.io.FileUtils.writeByteArrayToFile;
import static org.objectweb.asm.ClassReader.EXPAND_FRAMES;
import static org.objectweb.asm.ClassWriter.COMPUTE_FRAMES;
import static org.objectweb.asm.Opcodes.ASM9;

public class Log4jPath {

	public static byte[] patchLookup(InputStream in) throws IOException {
		final ClassReader cr = new ClassReader(in);
		final ClassWriter cw = new ClassWriter(cr, COMPUTE_FRAMES);

		cr.accept(new ClassVisitor(ASM9, cw) {
			@Override
			public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] e) {
				if (name.equals("lookup")) {
					MethodVisitor mv = super.visitMethod(access, name, desc, signature, e);

					return new AdviceAdapter(api, mv, access, name, desc) {
						@Override
						protected void onMethodEnter() {
							push((String) null);
							mv.visitInsn(ARETURN);
						}
					};
				}

				return super.visitMethod(access, name, desc, signature, e);
			}
		}, EXPAND_FRAMES);

		return cw.toByteArray();
	}

	public static byte[] pathJar(JarFile jarFile) throws IOException {
		ByteArrayOutputStream           out = new ByteArrayOutputStream();
		JarOutputStream                 zos = new JarOutputStream(out);
		Enumeration<? extends JarEntry> je  = jarFile.entries();

		while (je.hasMoreElements()) {
			JarEntry    zip      = je.nextElement();
			InputStream in       = jarFile.getInputStream(zip);
			String      fileName = zip.getName();
			JarEntry    z        = new JarEntry(zip.getName());
			zos.putNextEntry(z);

			if ("org/apache/logging/log4j/core/lookup/JndiLookup.class".equalsIgnoreCase(fileName)) {
				InputStream inputStream = IOUtils.toBufferedInputStream(in);
				byte[]      bytes       = patchLookup(inputStream);
				zos.write(bytes);
			} else {
				zos.write(IOUtils.toByteArray(in));
			}

			zos.closeEntry();
		}

		zos.close();
		jarFile.close();

		return out.toByteArray();
	}

	public static void pathSpringBoot(File jarFile, File pathFile) throws IOException {
		FileOutputStream out = new FileOutputStream(pathFile);
		JarOutputStream  zos = new JarOutputStream(out);
		JarFile          jf  = new JarFile(jarFile);

		Enumeration<? extends JarEntry> je = jf.entries();

		while (je.hasMoreElements()) {
			JarEntry             jarEntry = je.nextElement();
			byte[]               jarBytes = IOUtils.toByteArray(jf.getInputStream(jarEntry));
			ByteArrayInputStream in       = new ByteArrayInputStream(jarBytes);
			String               fileName = jarEntry.getName();
			JarEntry             ze       = new JarEntry(jarEntry.getName());

			if (fileName.contains("BOOT-INF/lib/") && fileName.contains("log4j")) {
				String tmpFileName = fileName.substring(fileName.lastIndexOf("/"));
				File   tmpDir      = FileUtils.getTempDirectory();
				File   tmpJar      = new File(tmpDir, tmpFileName);
				FileUtils.copyInputStreamToFile(in, tmpJar);

				JarFile tmpJarFile = new JarFile(tmpJar);
				jarBytes = pathJar(tmpJarFile);
			}

			ze.setMethod(JarEntry.STORED);
			ze.setSize(jarBytes.length);
			CRC32 crc32 = new CRC32();
			crc32.update(jarBytes, 0, jarBytes.length);
			ze.setCrc(crc32.getValue());
			zos.setLevel(Deflater.NO_COMPRESSION);
			zos.setMethod(JarEntry.STORED);

			zos.putNextEntry(ze);

			zos.write(jarBytes);
			zos.closeEntry();
		}

		zos.close();
		jf.close();
	}

	public static void patch(String path) throws IOException {
		File             file       = new File(path);
		JarFile          jarFile    = new JarFile(file);
		File             pathFile   = new File(path + ".patch");
		URL              jarURL     = new URL("jar:file:" + file.getAbsolutePath() + "!/BOOT-INF/lib/");
		JarURLConnection connection = (JarURLConnection) jarURL.openConnection();

		try {
			// SpringBoot Patch
			connection.getInputStream();
			pathSpringBoot(file, pathFile);
		} catch (FileNotFoundException e) {
			writeByteArrayToFile(pathFile, pathJar(jarFile));
		}
	}

	public static void main(String[] args) throws Exception {
		if (args.length < 1) {
			System.out.println("请输入jar路径！");
			return;
		}

		patch(args[0]);
	}

}
