/*
Copyright (c) 2019, 226332
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package CoffeCrypt;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Sha1 implements Hash {
    public static int BYTES_IN_CHUNK = 64;

    @Override
    public String encrypt(String input) {
        int[] hashWords = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
        // Each message must be processed into 512-bit blocks with additional bit and length information at the end.
        for (byte[] chunk : chopMessage(input)) {
            // 512-bit chunk is split into 16 32-bit words.
            int[] chunkWords = chunkToWords(chunk);
            for (int t = 16; t < 80; t++) {
                chunkWords[t] = Integer.rotateLeft(
                        chunkWords[t - 3] ^ chunkWords[t - 8] ^ chunkWords[t - 14] ^ chunkWords[t - 16], 1);
            }
            int a = hashWords[0];
            int b = hashWords[1];
            int c = hashWords[2];
            int d = hashWords[3];
            int e = hashWords[4];
            for (int t = 0; t < 80; t++) {
                int temp = Integer.rotateLeft(a, 5) + logicalFunc(t, b, c, d) +
                        e + chunkWords[t] + getCipherConst(t);
                e = d;
                d = c;
                c = Integer.rotateLeft(b, 30);
                b = a;
                a = temp;
            }
            hashWords[0] += a;
            hashWords[1] += b;
            hashWords[2] += c;
            hashWords[3] += d;
            hashWords[4] += e;
        }
        return hashWordsToString(hashWords);
    }

    public String hashWordsToString(int[] hashWords) {
        StringBuilder sb = new StringBuilder();
        for (int h : hashWords) {
            sb.append(Integer.toUnsignedString(h, 16));
        }
        return sb.toString();
    }

    public int logicalFunc(int t, int b, int c, int d) {
        assert (t >= 0 && t < 80);
        if (t < 20) {
            return (b & c) | ((~b) & d);
        } else if (t < 40 || 60 <= t) {
            return (b ^ c ^ d);
        }
        return (b & c) | (b & d) | (c & d);
    }

    public int getCipherConst(int t) {
        assert (t >= 0 && t < 80);
        if (t < 20) {
            return 0x5A827999;
        } else if (t < 40) {
            return 0x6ED9EBA1;
        } else if (t < 60) {
            return 0x8F1BBCDC;
        }
        return 0xCA62C1D6;
    }

    public int[] chunkToWords(byte[] chunk) {
        int[] words = new int[81];
        for (int i = 0; i < chunk.length / Integer.BYTES; i++) {
            int j = i * Integer.BYTES;
            words[i] = (chunk[j] & 0xff) << 24 | (chunk[j + 1] & 0xff) << 16
                    | (chunk[j + 2] & 0xff) << 8 | (chunk[j + 3] & 0xff);
        }
        return words;
    }

    public byte[] padMessage(String input) {
        byte[] bytesInput = input.getBytes();
        long inputBits = bytesInput.length * 8;
        int bytesHeader = Long.BYTES + Byte.BYTES;
        int bytesToPad = BYTES_IN_CHUNK - ((bytesInput.length + bytesHeader) % BYTES_IN_CHUNK);
        byte[] inputPadded = new byte[bytesInput.length + bytesToPad + bytesHeader];
        System.arraycopy(bytesInput, 0, inputPadded, 0, bytesInput.length);
        inputPadded[bytesInput.length] = (byte) 0x80;
        for (int j = 0; j < Long.BYTES; j++) {
            inputPadded[inputPadded.length - j - 1] = (byte) ((inputBits >>> 8 * j) & 0xff);
        }
        return inputPadded;
    }

    public List<byte[]> chopMessage(String input) {
        byte[] inputPadded = padMessage(input);
        assert inputPadded.length % BYTES_IN_CHUNK == 0;
        List<byte[]> chunks = new ArrayList<>();
        for (int i = 0; i < inputPadded.length / BYTES_IN_CHUNK; i++) {
            int startIdx = BYTES_IN_CHUNK * i;
            byte[] chunk = Arrays.copyOfRange(inputPadded, startIdx, startIdx + BYTES_IN_CHUNK);
            chunks.add(chunk);
        }
        return chunks;
    }
}
