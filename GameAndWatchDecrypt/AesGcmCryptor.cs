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
    class AesGcmCryptor : IDisposable
    {
        AesGcm aes;
        byte[] iv;
        private bool disposedValue;

        public AesGcmCryptor(byte[] key, byte[] iv)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (iv == null) throw new ArgumentNullException(nameof(iv));
            if (iv.Length != AesGcm.NonceByteSizes.MinSize)
                throw new ArgumentException("Invalid IV size.", nameof(iv));

            aes = new AesGcm(key);
            this.iv = iv;
        }

        public byte[] Decrypt(byte[] ciphertext, byte[] tag)
        {
            CheckDisposed();
            if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
            if (tag == null) throw new ArgumentNullException(nameof(tag));

            byte[] ciphertextDup = (byte[])ciphertext.Clone();
            byte[] tagDup = (byte[])tag.Clone();
            Utils.ShuffleEndianess(ciphertextDup);
            Utils.ShuffleEndianess(tagDup);

            byte[] plaintext = new byte[ciphertext.Length];
            aes.Decrypt(iv, ciphertextDup, tagDup, plaintext);

            Utils.ShuffleEndianess(plaintext);
            return plaintext;
        }

        public byte[] Encrypt(byte[] plaintext, out byte[] tag)
        {
            CheckDisposed();
            if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));

            byte[] plaintextDup = (byte[])plaintext.Clone();
            Utils.ShuffleEndianess(plaintextDup);

            byte[] ciphertext = new byte[plaintext.Length];
            tag = new byte[16];
            aes.Encrypt(iv, plaintextDup, ciphertext, tag);

            Utils.ShuffleEndianess(ciphertext);
            Utils.ShuffleEndianess(tag);
            return ciphertext;
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
