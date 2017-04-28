package com.tencent.karaoke.signTool;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.util.zip.ZipFile;

import com.tencent.karaoke.apksign.ApkSignerV2;
import com.tencent.karaoke.apksign.ApkSignerV2.ApkParseException;
import com.tencent.karaoke.apksign.ZipUtils;

public class signApkTool {
    private static String apkPath = "D:\\karoke-project\\TrimApk\\AndroidSignApkToolV2\\testapk\\testapk.apk";//表示的意思是"kara"

    private static String apkDestPath = "D:\\karoke-project\\TrimApk\\AndroidSignApkToolV2\\testapk\\writeChanael.apk";

    private static String apkdeleteChanaelPath = "D:\\karoke-project\\TrimApk\\AndroidSignApkToolV2\\testapk\\deleteChanael.apk";
    public static final int CHANEL_ID = 0x6b617261;
    public static String CHANAEL = "chanael";

    public static void printoutString(String str) {
        System.out.println(str);
    }

    public static void printHexLong(int num){
        byte temp[]=new byte[4];
        temp[0]= (byte) (num&0xff);
        temp[1]=(byte)(num>>8&0xff);
        temp[2]=(byte)(num>>16&0xff);
        temp[3]=(byte)(num>>24&0xff);
        printHexString(temp);
    }

    public static void printHexString(byte b[]) {
        for (int i = 0; i < b.length; i++) {
            System.out.print(String.format("byte[%d]=%s ", i, Integer.toHexString(b[i] & 0xFF)));
        }
        System.out.println();
    }

    /**
     * @param inputApk
     * 读取apk中签名块中的渠道号信息
     */
    public void readChanael(ByteBuffer inputApk){
        if (inputApk == null) {
            printoutString("after buffer is null");
            return;
        }

        ByteBuffer originalInputApk = inputApk;
        inputApk = originalInputApk.slice();
        inputApk.order(ByteOrder.LITTLE_ENDIAN);

        try {
            int eocdOffset = ZipUtils.findZipEndOfCentralDirectoryRecord(inputApk);  //核心目录结束区开头偏移
            if (eocdOffset == -1) {
                throw new ApkParseException("Failed to locate ZIP End of Central Directory");
            }
            if (ZipUtils.isZip64EndOfCentralDirectoryLocatorPresent(inputApk, eocdOffset)) {
                throw new ApkParseException("ZIP64 format not supported");
            }

            inputApk.position(eocdOffset);
            long centralDirSizeLong = ZipUtils.getZipEocdCentralDirectorySizeBytes(inputApk);
            if (centralDirSizeLong > Integer.MAX_VALUE) {
                throw new ApkParseException(
                        "ZIP Central Directory size out of range: " + centralDirSizeLong);
            }
            int centralDirSize = (int) centralDirSizeLong;  //核心目录大小
            long centralDirOffsetLong = ZipUtils.getZipEocdCentralDirectoryOffset(inputApk);
            if (centralDirOffsetLong > Integer.MAX_VALUE) {
                throw new ApkParseException(
                        "ZIP Central Directory offset in file out of range: " + centralDirOffsetLong);
            }
            int centralDirOffset = (int) centralDirOffsetLong;  //核心目录偏移处,在往上就应该是签名块了，先读16个字节，读个魔法数验证下
            //验证核心中央目录
            inputApk.position(centralDirOffset);

            int expectedEocdOffset = centralDirOffset + centralDirSize;
            if (expectedEocdOffset < centralDirOffset) {
                throw new ApkSignerV2.ApkParseException("ZIP Central Directory extent too large. Offset: " + centralDirOffset + ", size: " + centralDirSize);
            }

            if (eocdOffset != expectedEocdOffset) {
                throw new ApkSignerV2.ApkParseException("ZIP Central Directory not immeiately followed by ZIP End of Central Directory. CD end: " + expectedEocdOffset + ", EoCD start: " + eocdOffset);
            }

            inputApk.position(centralDirOffset - 16);
            byte[] magic = new byte[16];
            inputApk.get(magic);

            printoutString("magic is bellows");
            printHexString(magic);

            for (int i = 0; i < 16; i++) {
                if (magic[i] != ApkSignerV2UtilTool.APK_SIGNING_BLOCK_MAGIC[i]) {
                    printoutString("magic is not equal,please check whether has v2 signature block");
                    throw new ApkSignerV2.ApkParseException("magic is not equal");
                }
            }

            inputApk.position(centralDirOffset - 24);
            long v2SignatureBlockSizeExcludeFirst8ByteSizeLong = inputApk.getLong();
            if(v2SignatureBlockSizeExcludeFirst8ByteSizeLong>Integer.MAX_VALUE){
                printoutString("v2SignatureBlockSizeExcludeFirst8ByteSizeLong exceed 4G");
                throw new ApkSignerV2.ApkParseException("sizeexceed");
            }
            int v2SignatureBlockSizeExcludeFirst8ByteSize=(int)v2SignatureBlockSizeExcludeFirst8ByteSizeLong;
            int v2SignatureBlockOffset=centralDirOffset-v2SignatureBlockSizeExcludeFirst8ByteSize-8;
            inputApk.position(v2SignatureBlockOffset);
            long v2SignatureFisrt8ByteBlockSizeLong=inputApk.getLong();
            if(v2SignatureFisrt8ByteBlockSizeLong!=v2SignatureBlockSizeExcludeFirst8ByteSizeLong){
                printoutString("verify signature v2Signature Size error");
                throw new ApkSignerV2.ApkParseException("v2Signature BlockSize is not equal");
            }else{
                printoutString("v2Signature BlockSize is equal");
            }
            long v2SchemeBlockSizeMinus4ByteLong=inputApk.getLong();
            long v2SchemeBlockSizeLong=v2SchemeBlockSizeMinus4ByteLong-4;
            int v2BlockSchemeId = inputApk.getInt();
            printoutString("verify v2SchemeId is 0x7109871a");
            printHexLong(v2BlockSchemeId);
            if (v2BlockSchemeId != ApkSignerV2UtilTool.APK_SIGNATURE_SCHEME_V2_BLOCK_ID) {
                printoutString("v2SchemeId is not valid,please check");
                throw new ApkSignerV2.ApkParseException("v2SchemeId is not valid");
            }
            int v2SchemeBlockSize=(int)v2SchemeBlockSizeLong;
            inputApk.position(v2SignatureBlockOffset+8+8+4+v2SchemeBlockSize);
            int chanaelId=inputApk.getInt();
            printoutString("verify chanaelId is 0x6b617261");
            printHexLong(chanaelId);
            if(chanaelId!=CHANEL_ID){
                printoutString("v2SchemeChanelId is not valid,please check");
                throw new ApkSignerV2.ApkParseException("v2SchemeChanelId is not valid");
            }
            int chanaelLength=v2SignatureBlockSizeExcludeFirst8ByteSize-8-4-v2SchemeBlockSize-4-8-16;
            printoutString("The Chanael Length is "+chanaelLength);
            byte []chanaelByte=new byte[chanaelLength];
            inputApk.get(chanaelByte);

            try{
            String chanael=new String(chanaelByte,Charset.forName("UTF-8"));
            printoutString("读取的渠道为: "+chanael);
            }catch (Exception e){
                printoutString("make chanael error"+e.getMessage());
                e.printStackTrace();
            }
        }catch (Exception e){
            printoutString("读取渠道号发生错误"+e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     *
     * @param v2signedApk
     * @return
     * 删除渠道号，还原apk原来信息
     */
    public ByteBuffer[] afterDeleteChanael(ByteBuffer v2signedApk) throws ApkParseException {

        if (v2signedApk == null) {
            printoutString("buffer is null");
            return null;
        }

        ByteBuffer originalInputApk = v2signedApk;
        v2signedApk = originalInputApk.slice();
        v2signedApk.order(ByteOrder.LITTLE_ENDIAN);
        try {
            int eocdOffset = ZipUtils.findZipEndOfCentralDirectoryRecord(v2signedApk);
            if (eocdOffset == -1) {
                throw new ApkParseException("Failed to locate ZIP End of Central Directory");
            }
            if (ZipUtils.isZip64EndOfCentralDirectoryLocatorPresent(v2signedApk, eocdOffset)) {
                throw new ApkParseException("ZIP64 format not supported");
            }

            v2signedApk.position(eocdOffset);
            long centralDirSizeLong = ZipUtils.getZipEocdCentralDirectorySizeBytes(v2signedApk);
            if (centralDirSizeLong > Integer.MAX_VALUE) {
                throw new ApkParseException("ZIP Central Directory size out of range: " + centralDirSizeLong);
            }

            int centralDirSize = (int) centralDirSizeLong;
            long centralDirOffsetLong = ZipUtils.getZipEocdCentralDirectoryOffset(v2signedApk);
            if (centralDirOffsetLong > Integer.MAX_VALUE) {
                throw new ApkParseException("ZIP Central Directory offset in file out of range: " + centralDirOffsetLong);
            }

            int centralDirOffset = (int) centralDirOffsetLong;

            int expectedEocdOffset = centralDirOffset + centralDirSize;
            if (expectedEocdOffset < centralDirOffset) {
                throw new ApkParseException("ZIP Central Directory extent too large. Offset: " + centralDirOffset + ", size: " + centralDirSize);
            }

            if (eocdOffset != expectedEocdOffset) {
                throw new ApkParseException("ZIP Central Directory not immeiately followed by ZIP End of Central Directory. CD end: " + expectedEocdOffset + ", EoCD start: " + eocdOffset);
            }

            v2signedApk.position(centralDirOffset - 16);
            byte[] magic = new byte[16];
            v2signedApk.get(magic);

            printoutString("magic is bellows");
            printHexString(magic);

            for (int i = 0; i < 16; i++) {
                if (magic[i] != ApkSignerV2UtilTool.APK_SIGNING_BLOCK_MAGIC[i]) {
                    printoutString("magic is not equal,please check whether has v2 signature block");
                    throw new ApkParseException("magic is not equal");
                }
            }

            v2signedApk.position(centralDirOffset - 24);
            long v2SignatureBlockSizeExcludeFirst8ByteSizeLong = v2signedApk.getLong();
            int v2SignatureBlockSizeExcludeFirst8ByteSize=(int)v2SignatureBlockSizeExcludeFirst8ByteSizeLong;

            int v2SignatureBlockOffset=centralDirOffset-v2SignatureBlockSizeExcludeFirst8ByteSize-8;
            v2signedApk.position(v2SignatureBlockOffset);
            long v2SignatureFisrt8ByteBlockSizeLong=v2signedApk.getLong();
            if(v2SignatureFisrt8ByteBlockSizeLong!=v2SignatureBlockSizeExcludeFirst8ByteSizeLong){
                printoutString("verify signature v2Signature Size error");
                throw new ApkSignerV2.ApkParseException("v2Signature BlockSize is not equal");
            }else{
                printoutString("v2Signature BlockSize is equal");
            }
            long v2SchemeBlockSizeMinus4ByteLong=v2signedApk.getLong();
            long v2SchemeBlockSizeLong=v2SchemeBlockSizeMinus4ByteLong-4;
            int v2BlockSchemeId = v2signedApk.getInt();
            printoutString("verify v2SchemeId is 0x7109871a");
            printHexLong(v2BlockSchemeId);
            if (v2BlockSchemeId != ApkSignerV2UtilTool.APK_SIGNATURE_SCHEME_V2_BLOCK_ID) {
                printoutString("v2SchemeId is not valid,please check");
                throw new ApkSignerV2.ApkParseException("v2SchemeId is not valid");
            }
            int v2SchemeBlockSize=(int)v2SchemeBlockSizeLong;
            v2signedApk.position(v2SignatureBlockOffset+8+8+4+v2SchemeBlockSize);
            int chanaelId=v2signedApk.getInt();
            printoutString("verify chanaelId is 0x6b617261");
            printHexLong(chanaelId);
            if(chanaelId!=CHANEL_ID){
                printoutString("v2SchemeChanelId is not valid,please check");
                throw new ApkSignerV2.ApkParseException("v2SchemeChanelId is not valid");
            }
            int chanaelLength=v2SignatureBlockSizeExcludeFirst8ByteSize-8-4-v2SchemeBlockSize-4-8-16;
            printoutString("The Chanael Length is "+chanaelLength);
            byte []chanaelByte=new byte[chanaelLength];
            v2signedApk.get(chanaelByte);

            try{
                String chanael=new String(chanaelByte,Charset.forName("UTF-8"));
                printoutString("读取的渠道为: "+chanael);
            }catch (Exception e){
                printoutString("make chanael error"+e.getMessage());
                e.printStackTrace();
            }

            v2signedApk.clear();

            byte[] _tempBeforeV2Signature = new byte[v2SignatureBlockOffset];
            v2signedApk.get(_tempBeforeV2Signature);
            ByteBuffer beforeV2Signature = ByteBuffer.wrap(_tempBeforeV2Signature);
            beforeV2Signature.order(v2signedApk.order());

            byte[] v2SignatureBytes = new byte[v2SignatureBlockSizeExcludeFirst8ByteSize + 8];
            v2signedApk.get(v2SignatureBytes);
            ByteBuffer initalV2Signature = ByteBuffer.wrap(v2SignatureBytes);
            initalV2Signature.order(v2signedApk.order());

            byte[] v2SchemeBlockBytes = new byte[v2SchemeBlockSize];
            ByteBuffer tempbuffer = ByteBuffer.wrap(v2SignatureBytes);
            tempbuffer.order(ByteOrder.LITTLE_ENDIAN);
            tempbuffer.position(16);

            byte[] tempid = new byte[4];
            tempbuffer.get(tempid);
            printoutString("when write signature,first check the v2schemeId is 0x7109871a");
            printHexString(tempid);

            tempbuffer.position(20);
            tempbuffer.get(v2SchemeBlockBytes);

            byte[] _tempCentralDirectory = new byte[eocdOffset - centralDirOffset];
            v2signedApk.get(_tempCentralDirectory);
            ByteBuffer initalCentralDirectory = ByteBuffer.wrap(_tempCentralDirectory);
            initalCentralDirectory.order(v2signedApk.order());

            byte[] eocdBytes = new byte[v2signedApk.remaining()];
            v2signedApk.get(eocdBytes);
            ByteBuffer eocd = ByteBuffer.wrap(eocdBytes);
            eocd.order(v2signedApk.order());

            ByteBuffer postDeleteChanaelOfApkSigningBlock = ByteBuffer.wrap(getDeleteChanaelSignatureBlock(v2SchemeBlockBytes));

            printoutString("beforeCentralDirOffset is ");
            printHexLong(centralDirOffset);
            int afterCentralDirOffset = centralDirOffset-4-chanaelLength;
            printoutString("afterCentralDirOffset is ");
            printHexLong(afterCentralDirOffset);

            eocd.clear();
            ZipUtils.setZipEocdCentralDirectoryOffset(eocd, afterCentralDirOffset);

            originalInputApk.position(originalInputApk.limit());

            beforeV2Signature.clear();
            postDeleteChanaelOfApkSigningBlock.clear();
            initalCentralDirectory.clear();
            eocd.clear();

            return new ByteBuffer[]{beforeV2Signature, postDeleteChanaelOfApkSigningBlock, initalCentralDirectory, eocd};
        } catch (ApkSignerV2.ApkParseException e)
            {
                printoutString("ApkParseException " + e.getMessage());
                e.printStackTrace();
            }
            return null;
    }

    public void verifyAfterWriteChanael(ByteBuffer inputApk) {
        if (inputApk == null) {
            printoutString("after buffer is null");
            return;
        }

        printoutString("verify starting......");
        ByteBuffer originalInputApk = inputApk;
        inputApk = originalInputApk.slice();
        inputApk.order(ByteOrder.LITTLE_ENDIAN);

        try {
            int eocdOffset = ZipUtils.findZipEndOfCentralDirectoryRecord(inputApk);  //核心目录结束区开头偏移
            if (eocdOffset == -1) {
                throw new ApkParseException("Failed to locate ZIP End of Central Directory");
            }
            if (ZipUtils.isZip64EndOfCentralDirectoryLocatorPresent(inputApk, eocdOffset)) {
                throw new ApkParseException("ZIP64 format not supported");
            }


            inputApk.position(eocdOffset);
            long centralDirSizeLong = ZipUtils.getZipEocdCentralDirectorySizeBytes(inputApk);
            if (centralDirSizeLong > Integer.MAX_VALUE) {
                throw new ApkParseException(
                        "ZIP Central Directory size out of range: " + centralDirSizeLong);
            }
            int centralDirSize = (int) centralDirSizeLong;  //核心目录大小
            long centralDirOffsetLong = ZipUtils.getZipEocdCentralDirectoryOffset(inputApk);
            if (centralDirOffsetLong > Integer.MAX_VALUE) {
                throw new ApkParseException(
                        "ZIP Central Directory offset in file out of range: " + centralDirOffsetLong);
            }
            int centralDirOffset = (int) centralDirOffsetLong;  //核心目录偏移处,在往上就应该是签名块了，先读16个字节，读个魔法数验证下

            //验证核心中央目录
            inputApk.position(centralDirOffset);
            byte[] temp=new byte[4];
            inputApk.get(temp);

            printoutString("下面打印出核心中央目录magic是否为0x02014b50");
            //应该是特殊符号
            printHexString(temp);

            //下面验证下是否合理，这个可以不用加，可以放在写完校验下。
            int expectedEocdOffset = centralDirOffset + centralDirSize;
            if (expectedEocdOffset < centralDirOffset) {
                throw new ApkParseException(
                        "ZIP Central Directory extent too large. Offset: " + centralDirOffset
                                + ", size: " + centralDirSize);
            }
            if (eocdOffset != expectedEocdOffset) {
                throw new ApkParseException(
                        "ZIP Central Directory not immeiately followed by ZIP End of"
                                + " Central Directory. CD end: " + expectedEocdOffset
                                + ", EoCD start: " + eocdOffset);
            }

            printoutString("verify end,祝贺校验成功!!");
        }catch(ApkParseException e){
            printoutString("ApkParseException " + e.getMessage());
            e.printStackTrace();
        }
    }

    public ByteBuffer[] getAfterWriteChanaelOfApkBuffers(ByteBuffer inputApk, String chanael) {
        if (inputApk == null) {
            printoutString("buffer is null");
            return null;
        }

        ByteBuffer originalInputApk = inputApk;
        inputApk = originalInputApk.slice();
        inputApk.order(ByteOrder.LITTLE_ENDIAN);
        try
        {
            int eocdOffset = ZipUtils.findZipEndOfCentralDirectoryRecord(inputApk);
            if (eocdOffset == -1) {
                throw new ApkSignerV2.ApkParseException("Failed to locate ZIP End of Central Directory");
            }
            if (ZipUtils.isZip64EndOfCentralDirectoryLocatorPresent(inputApk, eocdOffset)) {
                throw new ApkSignerV2.ApkParseException("ZIP64 format not supported");
            }

            inputApk.position(eocdOffset);
            long centralDirSizeLong = ZipUtils.getZipEocdCentralDirectorySizeBytes(inputApk);
            if (centralDirSizeLong > Integer.MAX_VALUE) {
                throw new ApkSignerV2.ApkParseException("ZIP Central Directory size out of range: " + centralDirSizeLong);
            }

            int centralDirSize = (int)centralDirSizeLong;
            long centralDirOffsetLong = ZipUtils.getZipEocdCentralDirectoryOffset(inputApk);
            if (centralDirOffsetLong > Integer.MAX_VALUE) {
                throw new ApkSignerV2.ApkParseException("ZIP Central Directory offset in file out of range: " + centralDirOffsetLong);
            }

            int centralDirOffset = (int)centralDirOffsetLong;

            int expectedEocdOffset = centralDirOffset + centralDirSize;
            if (expectedEocdOffset < centralDirOffset) {
                throw new ApkSignerV2.ApkParseException("ZIP Central Directory extent too large. Offset: " + centralDirOffset + ", size: " + centralDirSize);
            }

            if (eocdOffset != expectedEocdOffset) {
                throw new ApkSignerV2.ApkParseException("ZIP Central Directory not immeiately followed by ZIP End of Central Directory. CD end: " + expectedEocdOffset + ", EoCD start: " + eocdOffset);
            }

            inputApk.position(centralDirOffset - 16);
            byte[] magic = new byte[16];
            inputApk.get(magic);

            printoutString("magic is bellows");
            printHexString(magic);

            for (int i = 0; i < 16; i++) {
                if (magic[i] != ApkSignerV2UtilTool.APK_SIGNING_BLOCK_MAGIC[i]) {
                    printoutString("magic is not equal,please check whether has v2 signature block");
                    throw new ApkSignerV2.ApkParseException("magic is not equal");
                }
            }

            inputApk.position(centralDirOffset - 24);
            long v2SignatureBlockSizeExcludeFirst8ByteSizeLong = inputApk.getLong();
            long v2SchemeBlockSizeLong = v2SignatureBlockSizeExcludeFirst8ByteSizeLong - 36L;

            if ((v2SignatureBlockSizeExcludeFirst8ByteSizeLong > Integer.MAX_VALUE) || (v2SchemeBlockSizeLong > Integer.MAX_VALUE)) {
                throw new ApkSignerV2.ApkParseException("zip size exceed 4G");
            }

            int v2SignatureBlockSizeExcludeFirst8ByteSize = (int)v2SignatureBlockSizeExcludeFirst8ByteSizeLong;
            int v2SchemeBlockSize = (int)v2SchemeBlockSizeLong;

            int v2SignatureBlockOffset = centralDirOffset - v2SignatureBlockSizeExcludeFirst8ByteSize - 8;

            int v2SchemeIdOffset = v2SignatureBlockOffset + 16;

            inputApk.position(v2SchemeIdOffset);

            int v2BlockSchemeId = inputApk.getInt();
            if (v2BlockSchemeId != ApkSignerV2UtilTool.APK_SIGNATURE_SCHEME_V2_BLOCK_ID) {
                printoutString("v2SchemeId is not valid,please check");
                throw new ApkSignerV2.ApkParseException("v2SchemeId is not valid");
            }

            inputApk.position(v2SchemeIdOffset);
            byte[] _id = new byte[4];
            inputApk.get(_id);

            printoutString("v2schemeId is bellows");
            printHexString(_id);

            inputApk.clear();

            byte[] _tempBeforeV2Signature = new byte[v2SignatureBlockOffset];
            inputApk.get(_tempBeforeV2Signature);
            ByteBuffer beforeV2Signature = ByteBuffer.wrap(_tempBeforeV2Signature);
            beforeV2Signature.order(inputApk.order());

            byte[] v2SignatureBytes = new byte[v2SignatureBlockSizeExcludeFirst8ByteSize + 8];
            inputApk.get(v2SignatureBytes);
            ByteBuffer initalV2Signature = ByteBuffer.wrap(v2SignatureBytes);
            initalV2Signature.order(inputApk.order());

            byte[] v2SchemeBlockBytes = new byte[v2SchemeBlockSize];
            ByteBuffer tempbuffer = ByteBuffer.wrap(v2SignatureBytes);
            tempbuffer.order(ByteOrder.LITTLE_ENDIAN);
            tempbuffer.position(16);

            byte[] tempid = new byte[4];
            tempbuffer.get(tempid);
            printoutString("when write signature,first check the v2schemeId is 0x7109871a");
            printHexString(tempid);

            tempbuffer.position(20);
            tempbuffer.get(v2SchemeBlockBytes);

            byte[] _tempCentralDirectory = new byte[eocdOffset - centralDirOffset];
            inputApk.get(_tempCentralDirectory);
            ByteBuffer initalCentralDirectory = ByteBuffer.wrap(_tempCentralDirectory);
            initalCentralDirectory.order(inputApk.order());

            byte[] eocdBytes = new byte[inputApk.remaining()];
            inputApk.get(eocdBytes);
            ByteBuffer eocd = ByteBuffer.wrap(eocdBytes);
            eocd.order(inputApk.order());

            ByteBuffer postWriteChanaelOfApkSigningBlock = ByteBuffer.wrap(getAfterWriteChanaelSignatureBlock(v2SchemeBlockBytes, chanael));

            printoutString("beforeCentralDirOffset is ");
            printHexLong(centralDirOffset);
            int afterCentralDirOffset = centralDirOffset + 4 + chanael.getBytes(Charset.forName("UTF-8")).length;
            printoutString("afterCentralDirOffset is ");
            printHexLong(afterCentralDirOffset);

            eocd.clear();
            ZipUtils.setZipEocdCentralDirectoryOffset(eocd, afterCentralDirOffset);

            originalInputApk.position(originalInputApk.limit());

            beforeV2Signature.clear();
            postWriteChanaelOfApkSigningBlock.clear();
            initalCentralDirectory.clear();
            eocd.clear();

            return new ByteBuffer[] { beforeV2Signature, postWriteChanaelOfApkSigningBlock, initalCentralDirectory, eocd };
        }
        catch (ApkSignerV2.ApkParseException e)
        {
            printoutString("ApkParseException " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }


    public byte[] getAfterWriteChanaelSignatureBlock(byte[] v2SchemeBlockBytes, String chanael) throws ApkParseException {
        //上面就是原始的4个块,接下来开始重点改造第二个块，然后重写initalEocd对应的偏移即可喽。
        //String chanael="chanael";
        //byte postV2SinatureBytes[]=new byte[v2SignatureBytes.length+4+chanael.getBytes().length];
        if (v2SchemeBlockBytes == null || v2SchemeBlockBytes.length < 1) {
            printoutString("get v2SchemeBlockBytes is not correct");
            throw new ApkParseException("error get v2SchemeBlockBytes");
        }

        byte[] chanelBytes = chanael.getBytes(Charset.forName("UTF-8"));
        int resultSize =
                8 // size
                        + 8 + 4 + v2SchemeBlockBytes.length // v2Block as ID-value pair
                        + 4 + chanelBytes.length
                        + 8 // size
                        + 16 // magic
                ;
        //int resultSize=v2SignatureBytes.length+4+chanelBytes.length;
        ByteBuffer result = ByteBuffer.allocate(resultSize);
        result.order(ByteOrder.LITTLE_ENDIAN);
        long blockSizeFieldValue = resultSize - 8;
        result.putLong(blockSizeFieldValue); //被修改了

        long pairSizeFieldValue = 4 + v2SchemeBlockBytes.length; //这个值还没变
        result.putLong(pairSizeFieldValue);
        result.putInt(ApkSignerV2UtilTool.APK_SIGNATURE_SCHEME_V2_BLOCK_ID);
        result.put(v2SchemeBlockBytes);

        result.putInt(CHANEL_ID);
        result.put(chanelBytes);

        result.putLong(blockSizeFieldValue);
        result.put(ApkSignerV2UtilTool.APK_SIGNING_BLOCK_MAGIC);

        return result.array();
    }

    public byte[] getDeleteChanaelSignatureBlock(byte[] v2SchemeBlockBytes) throws ApkParseException {
        //上面就是原始的4个块,接下来开始重点改造第二个块，然后重写initalEocd对应的偏移即可喽。
        //String chanael="chanael";
        //byte postV2SinatureBytes[]=new byte[v2SignatureBytes.length+4+chanael.getBytes().length];
        if (v2SchemeBlockBytes == null || v2SchemeBlockBytes.length < 1) {
            printoutString("get v2SchemeBlockBytes is not correct");
            throw new ApkParseException("error get v2SchemeBlockBytes");
        }

        int resultSize =
                8 // size
                        + 8 + 4 + v2SchemeBlockBytes.length // v2Block as ID-value pair
                        + 8 // size
                        + 16 // magic
                ;
        //int resultSize=v2SignatureBytes.length+4+chanelBytes.length;
        ByteBuffer result = ByteBuffer.allocate(resultSize);
        result.order(ByteOrder.LITTLE_ENDIAN);
        long blockSizeFieldValue = resultSize - 8;
        result.putLong(blockSizeFieldValue); //被修改了

        long pairSizeFieldValue = 4 + v2SchemeBlockBytes.length; //这个值还没变
        result.putLong(pairSizeFieldValue);
        result.putInt(ApkSignerV2UtilTool.APK_SIGNATURE_SCHEME_V2_BLOCK_ID);
        result.put(v2SchemeBlockBytes);

        result.putLong(blockSizeFieldValue);
        result.put(ApkSignerV2UtilTool.APK_SIGNING_BLOCK_MAGIC);

        return result.array();
    }


    public static void main(String[] args) {
        if(args.length<2){
            printoutString("args length is not enough");
            return;
        }

        for (int index = 0; index < args.length; index++) {
            String arg = args[index];
            if(arg.equals("-input")){
                if(index==args.length-1){
                    printoutString("please checkout input");
                    return;
                }
                apkPath=args[++index];
            }else if(arg.equals("-output")){
                if(index==args.length-1){
                    printoutString("please checkout output");
                    return;
                }
                apkDestPath=args[++index];
            }else if(arg.equals("-chanael")){
                if(index==args.length-1){
                    printoutString("please checkout chanael");
                    return;
                }
                CHANAEL=args[++index];
            }else if(arg.equals("-delete")){
                if(index==args.length-1){
                    printoutString("please checkout chanael");
                    return;
                }
                apkdeleteChanaelPath=args[++index];
            }
        }

        System.out.println("WriteChanael begining...");
        signApkTool signApkTool = new signApkTool();
        ByteBuffer buffer = new ApkSignerV2UtilTool().getApkByteBuffer(apkPath);
        ByteBuffer[] apkBuffers = signApkTool.getAfterWriteChanaelOfApkBuffers(buffer, CHANAEL);
        long preApkLength = buffer.array().length;
        printoutString("原来apk大小为:" + preApkLength);
        File tempFile=new File(apkDestPath);
        if(tempFile.exists()){
            printoutString("destapk has exists,first delete it");
            tempFile.delete();
        }
        RandomAccessFile apkFile = null;
        RandomAccessFile deleteChanaelFile=null;
        //File apkFile=new File(apkDestPath);
        try {
            apkFile = new RandomAccessFile(apkDestPath, "rw");
            for (ByteBuffer contents : apkBuffers) {
                apkFile.write(contents.array());
            }
            int writeLength = 4 + CHANAEL.getBytes(Charset.forName("UTF-8")).length;
            long expectedLengthLong = preApkLength + writeLength;
            int expectedLength=(int)expectedLengthLong;

            printoutString("写入的字节数为:" + writeLength);
            printoutString("写入渠道后apk大小为:" + apkFile.length());
            if (expectedLength != apkFile.length()) {
                //printoutString("write chanael is not correct,please check");
            }else {
                printoutString("写入字节检查通过....");
            }

            ByteBuffer afterApkbuffer = new ApkSignerV2UtilTool().getApkByteBuffer(apkDestPath);

            signApkTool.verifyAfterWriteChanael(afterApkbuffer);

            printoutString("readChanael begin");
            signApkTool.readChanael(afterApkbuffer);

            ByteBuffer[] afterDeleteChanaelApk = signApkTool.afterDeleteChanael(afterApkbuffer);

            deleteChanaelFile=new RandomAccessFile(apkdeleteChanaelPath,"rw");
            for (ByteBuffer contents : afterDeleteChanaelApk) {
                deleteChanaelFile.write(contents.array());
            }
            printoutString("deleteChanael success");
        } catch (FileNotFoundException e) {
            printoutString("filenotFoundException " + e.getMessage());
            e.printStackTrace();
        } catch (IOException e) {
            printoutString("IOException " + e.getMessage());
            e.printStackTrace();
        } catch (ApkParseException e) {
            printoutString("ApkParseException " + e.getMessage());
            e.printStackTrace();
        } finally {
            try {
                apkFile.close();
                deleteChanaelFile.close();
            } catch (IOException e) {
                printoutString("apkFile close error"+e.getMessage());
                e.printStackTrace();
            }
        }
    }
}