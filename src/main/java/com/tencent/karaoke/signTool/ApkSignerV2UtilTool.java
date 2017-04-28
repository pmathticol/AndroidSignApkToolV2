package com.tencent.karaoke.signTool;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.jar.JarFile;

import com.tencent.karaoke.apksign.ApkSignerV2;

/**
 * Created by pisazzpan on 2016/11/19.
 */

public class ApkSignerV2UtilTool extends ApkSignerV2 {


    public ApkSignerV2UtilTool() {
        super();
    }

    public static void printoutString(String str){
        System.out.println(str);
    }
    /**
     * @param inputFile
     * @param chanelName 写chanelName到inputFile当中来
     */
//    public void writeChanael(JarFile inputFile, String chanelName) {
//
//        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream();
//        ByteBuffer preApkByteBuffer = ByteBuffer.wrap(new);
//    }

    /**
     * @param apkFileName
     * @return 得到apk的字节流，然后去包装成byteBuffer
     */
    public ByteBuffer getApkByteBuffer(String apkFileName) {
        try {
            RandomAccessFile randomAccessFile = new RandomAccessFile(apkFileName, "r");
            int apkLength = (int)randomAccessFile.length()&0xffffffff; //2^32-1,差不多4G了,apk包应该没有这么大
            printoutString("apklength="+apkLength);
            byte[] apk = new byte[apkLength];
            randomAccessFile.readFully(apk);
            ByteBuffer buffer=ByteBuffer.wrap(apk);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            return buffer;
        } catch (FileNotFoundException e) {
            printoutString("FileNotFoundException");
            e.printStackTrace();
        } catch (IOException e) {
            printoutString("IOException");
            e.printStackTrace();
        }
        return null;
    }

    public void readChanael(JarFile inputFile) {

    }
}
