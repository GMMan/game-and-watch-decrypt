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
using System.Security.Cryptography;
using System.Text;

namespace GameAndWatchDecrypt
{
    class OtfDecCryptor : IDisposable
    {
        Aes aes;
        ICryptoTransform cryptor;
        byte[] iv;
        readonly uint startAddress;
        readonly uint endAddress;
        private bool disposedValue;

        public OtfDecCryptor(byte[] key, byte[] iv, uint startAddress, uint endAddress)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (iv == null) throw new ArgumentNullException(nameof(iv));
            aes = Aes.Create();
            aes.Key = key;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            cryptor = aes.CreateEncryptor();
            this.iv = iv;
            // See OTFDEC_RxSTARTADDR and OTFDEC_RxENDADDR
            // MSB 4 bits not discarded for simplicity
            this.startAddress = startAddress & 0xfffff000;
            this.endAddress = (endAddress & 0xfffff000) | 0xfff;
        }

        public void Crypt(byte[] data, int offset, int length, uint dataBase)
        {
            CheckDisposed();
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (offset < 0 || offset > data.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset negative or past data length.");
            if (offset % (aes.BlockSize / 8) != 0)
                throw new ArgumentException(nameof(offset), "Offset is not multiple of block size.");
            if (length < 0)
                throw new ArgumentOutOfRangeException(nameof(length), "Length is negative");
            if (length % (aes.BlockSize / 8) != 0)
                throw new ArgumentException("Length is not a multiple of block size.", nameof(length));
            if (offset + length > data.Length)
                throw new ArgumentException("Offset and length past end of data.");
            if (dataBase % (aes.BlockSize / 8) != 0)
                throw new ArgumentException("Base address is not block aligned.", nameof(dataBase));

            uint currEndAddr = (uint)(dataBase + offset + length);
            for (uint i = (uint)(dataBase + offset); i < currEndAddr; i += (uint)(aes.BlockSize / 8))
            {
                uint ctr = i >> 4;
                iv[12] = (byte)((iv[12] & 0xf0) | (ctr >> 24));
                iv[13] = (byte)(ctr >> 16);
                iv[14] = (byte)(ctr >> 8);
                iv[15] = (byte)ctr;
                byte[] keyStream = cryptor.TransformFinalBlock(iv, 0, iv.Length);

                if (i >= startAddress && i <= endAddress)
                {
                    for (int j = 0; j < keyStream.Length; ++j)
                    {
                        // We'll do block reversing as required here
                        data[i - dataBase + j] ^= keyStream[keyStream.Length - 1 - j];
                    }
                }
            }
        }

        void CheckDisposed()
        {
            if (disposedValue) throw new ObjectDisposedException(GetType().FullName);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    cryptor.Dispose();
                    cryptor = null;
                    aes.Dispose();
                    aes = null;
                    iv = null;
                }

                disposedValue = true;
            }
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
