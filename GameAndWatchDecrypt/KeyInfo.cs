// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Game & Watch Encryption Utility
 * Copyright (C) 2020  Yukai Li
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;

namespace GameAndWatchDecrypt
{
    class KeyInfo
    {
        static readonly UInt32Converter converter = new UInt32Converter();

        public string FileBase { get; set; }

        public string[] OtfDecKey { get; set; }
        public string[] OtfDecNonce { get; set; }
        public string OtfDecVersion { get; set; }
        public int OtfDecRegion { get; set; }
        public string OtfDecStart { get; set; }
        public string OtfDecEnd { get; set; }

        public string[] AesGcmKey { get; set; }
        public string[] AesGcmIv { get; set; }
        public string AesGcmBase { get; set; }
        //public int AesGcmCopyNum { get; set; }
        public string AesGcmRegionLength { get; set; }
        public string AesGcmDataLength { get; set; }

        public bool IsOtfDecPresent
        {
            get
            {
                return OtfDecKey != null && OtfDecNonce != null && OtfDecVersion != null
                    && OtfDecStart != null && OtfDecEnd != null && OtfDecRegion > 0;
            }
        }

        public bool IsAesGcmPresent
        {
            get
            {
                return AesGcmKey != null && AesGcmIv != null && AesGcmBase != null
                    && AesGcmRegionLength != null && AesGcmDataLength != null /*&& AesGcmCopyNum > 0*/;
            }
        }

        public KeyInfoParsed Parse()
        {
            KeyInfoParsed parsed = new KeyInfoParsed();

            parsed.FileBase = ParseNum(FileBase, "SPI flash base address");

            if (IsOtfDecPresent)
            {
                if (OtfDecKey.Length != 4)
                    throw new Exception("Incorrect OTFDEC key length");
                uint[] otfDecKeyUInt = new uint[OtfDecKey.Length];
                for (int i = 0; i < OtfDecKey.Length; ++i)
                {
                    otfDecKeyUInt[i] = ParseNum(OtfDecKey[i], "OTFDEC key");
                }
                parsed.OtfDecKey = Utils.UIntArrayToBytes(otfDecKeyUInt);

                if (OtfDecNonce.Length != 2)
                    throw new Exception("Incorrect OTFDEC nonce length");
                uint[] otfDecNonceUInt = new uint[OtfDecNonce.Length];
                for (int i = 0; i < OtfDecNonce.Length; ++i)
                {
                    otfDecNonceUInt[i] = ParseNum(OtfDecNonce[i], "OTFDEC nonce");
                }

                // Create IV, all big endian:
                // 0-7: nonce
                // 8-9: zeroes
                // 10-11: version
                // 12 (top): region index
                // 12 (bottom)-15: start address (in memory space)
                byte[] otfDecIv = Utils.UIntArrayToBytes(otfDecNonceUInt);
                Array.Resize(ref otfDecIv, 16);

                uint otfDecVersionUInt = ParseNum(OtfDecVersion, "OTFDEC version");
                if (otfDecVersionUInt > ushort.MaxValue)
                    throw new Exception("OTFDEC version is too big to fit in ushort.");
                otfDecIv[10] = (byte)(otfDecVersionUInt >> 8);
                otfDecIv[11] = (byte)otfDecVersionUInt;

                if (OtfDecRegion < 1 || OtfDecRegion > 4)
                    throw new Exception("Invalid OTFDEC region");

                uint otfDecStartUInt = ParseNum(OtfDecStart, "OTFDEC region start");
                parsed.OtfDecStart = otfDecStartUInt;

                //otfDecStartUInt = (uint)((((OtfDecRegion - 1) & 3) << 28) | (otfDecStartUInt >> 4));
                // We'll put calculation of address inside the decryptor itself
                otfDecStartUInt = (uint)(((OtfDecRegion - 1) & 3) << 28);
                otfDecIv[12] = (byte)(otfDecStartUInt >> 24);
                otfDecIv[13] = (byte)(otfDecStartUInt >> 16);
                otfDecIv[14] = (byte)(otfDecStartUInt >> 8);
                otfDecIv[15] = (byte)(otfDecStartUInt >> 0);
                parsed.OtfDecIv = otfDecIv;

                parsed.OtfDecEnd = ParseNum(OtfDecEnd, "OTFDEC region end");

                if ((parsed.OtfDecStart & 0xf0000000) != (parsed.FileBase & 0xf0000000))
                    throw new Exception("OTFDEC region start does not match memory-mapped SPI base.");
                if ((parsed.OtfDecEnd & 0xf0000000) != (parsed.FileBase & 0xf0000000))
                    throw new Exception("OTFDEC region end does not match memory-mapped SPI base.");
            }

            if (IsAesGcmPresent)
            {
                if (AesGcmKey.Length != 4)
                    throw new Exception("Incorrect AES-GCM key length");
                uint[] aesGcmKeyUInt = new uint[AesGcmKey.Length];
                for (int i = 0; i < AesGcmKey.Length; ++i)
                {
                    aesGcmKeyUInt[i] = ParseNum(AesGcmKey[i], "AES-GCM key");
                }
                parsed.AesGcmKey = Utils.UIntArrayToBytes(aesGcmKeyUInt, false);

                if (AesGcmIv.Length != 3)
                    throw new Exception("Incorrect AES-GCM IV length");
                uint[] aesGcmIvUInt = new uint[AesGcmIv.Length];
                for (int i = 0; i < AesGcmIv.Length; ++i)
                {
                    aesGcmIvUInt[i] = ParseNum(AesGcmIv[i], "AES-GCM IV");
                }
                parsed.AesGcmIv = Utils.UIntArrayToBytes(aesGcmIvUInt, false);

                parsed.AesGcmBase = ParseNum(AesGcmBase, "AES-GCM base memory address");
                //parsed.AesGcmCopyNum = AesGcmCopyNum;
                parsed.AesGcmRegionLength = ParseNum(AesGcmRegionLength, "AES-GCM region length");
                parsed.AesGcmDataLength = ParseNum(AesGcmDataLength, "AES-GCM data length");
                if (parsed.AesGcmRegionLength < parsed.AesGcmDataLength + 0x10)
                    throw new Exception("AES-GCM data is too long for region.");
            }

            return parsed;
        }

        static uint ParseNum(string s, string name)
        {
            try
            {
                return (uint)converter.ConvertFromString(s);
            }
            catch
            {
                throw new FormatException($"Cannot parse {name} as an uint.");
            }
        }
    }
}
