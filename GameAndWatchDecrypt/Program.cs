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
using McMaster.Extensions.CommandLineUtils;
using System;
using System.IO;
using System.Text.Json;

namespace GameAndWatchDecrypt
{
    class Program
    {
        static KeyInfoParsed keyInfoParsed;
        static string configFilePath = "keyinfo.json";

        static int Main(string[] args)
        {
            var app = new CommandLineApplication
            {
                Name = Path.GetFileName(Environment.GetCommandLineArgs()[0]),
                FullName = "Game & Watch Encryption Utility",
                Description = "Manipulates encrypted sections within Game & Watch external flash image."
            };

            app.Command("import", config =>
            {
                config.FullName = "Import data";
                config.Description = "Imports data and NVRAM into flash image.";

                var configFilePathOpt = config.Option("--config|-c <key-file>", "Path to key file", CommandOptionType.SingleValue);
                configFilePathOpt.Accepts().ExistingFile();
                var mainDataPathOpt = config.Option("--data|-d <data-file>", "Path to main data", CommandOptionType.SingleValue);
                mainDataPathOpt.Accepts().ExistingFile();
                var nvram1PathOpt = config.Option("--nvram1|-n1 <nvram-file>", "Path to first NVRAM copy", CommandOptionType.SingleValue);
                nvram1PathOpt.Accepts().ExistingFile();
                var nvram2PathOpt = config.Option("--nvram2|-n2 <nvram-file>", "Path to second NVRAM copy", CommandOptionType.SingleValue);
                nvram2PathOpt.Accepts().ExistingFile();
                var flashImagePathArg = config.Argument("flash-image", "Path to flash image").IsRequired();
                flashImagePathArg.Accepts().LegalFilePath();
                config.HelpOption();

                config.OnExecute(() =>
                {
                    if (configFilePathOpt.HasValue())
                        configFilePath = configFilePathOpt.Value();

                    LoadKeyInfo();
                    using FileStream fs = File.OpenWrite(flashImagePathArg.Value);

                    if (mainDataPathOpt.HasValue())
                    {
                        if (!keyInfoParsed.IsOtfDecPresent)
                            throw new InvalidOperationException("No OTFDEC key available.");
                        byte[] otfdecData = File.ReadAllBytes(mainDataPathOpt.Value());
                        if (keyInfoParsed.OtfDecEnd - keyInfoParsed.FileBase + 1 < otfdecData.Length)
                            throw new InvalidDataException("Main data is too big to fit in OTFDEC region.");
                        using OtfDecCryptor otfdec = new OtfDecCryptor(keyInfoParsed.OtfDecKey, keyInfoParsed.OtfDecIv,
                            keyInfoParsed.OtfDecStart, keyInfoParsed.OtfDecEnd);
                        otfdec.Crypt(otfdecData, 0, otfdecData.Length, keyInfoParsed.FileBase);
                        fs.Write(otfdecData);
                    }

                    if (nvram1PathOpt.HasValue() || nvram2PathOpt.HasValue())
                    {
                        if (!keyInfoParsed.IsAesGcmPresent)
                            throw new InvalidOperationException("No AES-GCM key available.");

                        using AesGcmCryptor aes = new AesGcmCryptor(keyInfoParsed.AesGcmKey, keyInfoParsed.AesGcmIv);

                        if (nvram1PathOpt.HasValue())
                        {
                            byte[] aesData = File.ReadAllBytes(nvram1PathOpt.Value());
                            if (aesData.Length != keyInfoParsed.AesGcmDataLength)
                                throw new InvalidDataException("NVRAM 1 data length is not same as configured.");
                            long dataOffset = keyInfoParsed.AesGcmBase - keyInfoParsed.FileBase;
                            PadStreamToLength(fs, dataOffset);
                            fs.Seek(dataOffset, SeekOrigin.Begin);

                            byte[] tag;
                            byte[] ciphertext = aes.Encrypt(aesData, out tag);
                            fs.Write(tag);
                            fs.Write(ciphertext);
                        }

                        if (nvram2PathOpt.HasValue())
                        {
                            byte[] aesData = File.ReadAllBytes(nvram2PathOpt.Value());
                            if (aesData.Length != keyInfoParsed.AesGcmDataLength)
                                throw new InvalidDataException("NVRAM 2 data length is not same as configured.");
                            long dataOffset = keyInfoParsed.AesGcmBase - keyInfoParsed.FileBase + keyInfoParsed.AesGcmRegionLength;
                            PadStreamToLength(fs, dataOffset);
                            fs.Seek(dataOffset, SeekOrigin.Begin);

                            byte[] tag;
                            byte[] ciphertext = aes.Encrypt(aesData, out tag);
                            fs.Write(tag);
                            fs.Write(ciphertext);
                        }
                    }
                });
            });

            app.Command("export", config =>
            {
                config.FullName = "Export data";
                config.Description = "Exports data and NVRAM to decrypted files.";

                var configFilePathOpt = config.Option("--config|-c <key-file>", "Path to key file", CommandOptionType.SingleValue);
                configFilePathOpt.Accepts().ExistingFile();
                var mainDataPathOpt = config.Option("--data|-d <data-file>", "Path to main data", CommandOptionType.SingleValue);
                mainDataPathOpt.Accepts().LegalFilePath();
                var nvram1PathOpt = config.Option("--nvram1|-n1 <nvram-file>", "Path to first NVRAM copy", CommandOptionType.SingleValue);
                nvram1PathOpt.Accepts().LegalFilePath();
                var nvram2PathOpt = config.Option("--nvram2|-n2 <nvram-file>", "Path to second NVRAM copy", CommandOptionType.SingleValue);
                nvram2PathOpt.Accepts().LegalFilePath();
                var flashImagePathArg = config.Argument("flash-image", "Path to flash image").IsRequired();
                flashImagePathArg.Accepts().ExistingFile();
                config.HelpOption();

                config.OnExecute(() =>
                {
                    if (configFilePathOpt.HasValue())
                        configFilePath = configFilePathOpt.Value();

                    LoadKeyInfo();
                    using FileStream fs = File.OpenRead(flashImagePathArg.Value);
                    BinaryReader br = new BinaryReader(fs);

                    if (mainDataPathOpt.HasValue())
                    {
                        if (!keyInfoParsed.IsOtfDecPresent)
                            throw new InvalidOperationException("No OTFDEC key available.");

                        byte[] otfdecData = br.ReadBytes((int)(keyInfoParsed.OtfDecEnd - keyInfoParsed.FileBase + 1));

                        using OtfDecCryptor otfdec = new OtfDecCryptor(keyInfoParsed.OtfDecKey, keyInfoParsed.OtfDecIv,
                            keyInfoParsed.OtfDecStart, keyInfoParsed.OtfDecEnd);
                        otfdec.Crypt(otfdecData, 0, otfdecData.Length, keyInfoParsed.FileBase);
                        File.WriteAllBytes(mainDataPathOpt.Value(), otfdecData);
                    }

                    if (nvram1PathOpt.HasValue() || nvram2PathOpt.HasValue())
                    {
                        if (!keyInfoParsed.IsAesGcmPresent)
                            throw new InvalidOperationException("No AES-GCM key available.");

                        using AesGcmCryptor aes = new AesGcmCryptor(keyInfoParsed.AesGcmKey, keyInfoParsed.AesGcmIv);

                        if (nvram1PathOpt.HasValue())
                        {
                            long dataOffset = keyInfoParsed.AesGcmBase - keyInfoParsed.FileBase;
                            fs.Seek(dataOffset, SeekOrigin.Begin);

                            byte[] tag = br.ReadBytes(16);
                            byte[] ciphertext = br.ReadBytes((int)keyInfoParsed.AesGcmDataLength);
                            byte[] aesData = aes.Decrypt(ciphertext, tag);

                            File.WriteAllBytes(nvram1PathOpt.Value(), aesData);
                        }

                        if (nvram2PathOpt.HasValue())
                        {
                            long dataOffset = keyInfoParsed.AesGcmBase - keyInfoParsed.FileBase + keyInfoParsed.AesGcmRegionLength;
                            fs.Seek(dataOffset, SeekOrigin.Begin);

                            byte[] tag = br.ReadBytes(16);
                            byte[] ciphertext = br.ReadBytes((int)keyInfoParsed.AesGcmDataLength);
                            byte[] aesData = aes.Decrypt(ciphertext, tag);

                            File.WriteAllBytes(nvram2PathOpt.Value(), aesData);
                        }
                    }
                });
            });

            app.Command("otfdec", config =>
            {
                config.FullName = "Perform OTFDEC";
                config.Description = "Performs OTFDEC on a file.";

                var configFilePathOpt = config.Option("--config|-c <key-file>", "Path to key file", CommandOptionType.SingleValue);
                configFilePathOpt.Accepts().ExistingFile();
                var dataPathArg = config.Argument("data-path", "Path to file to process").IsRequired();
                dataPathArg.Accepts().ExistingFile();
                config.HelpOption();

                config.OnExecute(() =>
                {
                    if (configFilePathOpt.HasValue())
                        configFilePath = configFilePathOpt.Value();

                    LoadKeyInfo();
                    if (!keyInfoParsed.IsOtfDecPresent)
                        throw new InvalidOperationException("No OTFDEC key available.");

                    byte[] otfdecData = File.ReadAllBytes(dataPathArg.Value);

                    using OtfDecCryptor otfdec = new OtfDecCryptor(keyInfoParsed.OtfDecKey, keyInfoParsed.OtfDecIv,
                        keyInfoParsed.FileBase, (uint)(keyInfoParsed.FileBase + otfdecData.Length));
                    otfdec.Crypt(otfdecData, 0, otfdecData.Length, keyInfoParsed.FileBase);

                    File.WriteAllBytes(dataPathArg.Value, otfdecData);
                });
            });

            app.Command("aesdec", config =>
            {
                config.FullName = "Perform AES-GCM decryption";
                config.Description = "Performs AES-GCM decryption on a file.";

                var configFilePathOpt = config.Option("--config|-c <key-file>", "Path to key file", CommandOptionType.SingleValue);
                configFilePathOpt.Accepts().ExistingFile();
                var dataPathArg = config.Argument("data-path", "Path to file to process").IsRequired();
                dataPathArg.Accepts().ExistingFile();
                config.HelpOption();

                config.OnExecute(() =>
                {
                    if (configFilePathOpt.HasValue())
                        configFilePath = configFilePathOpt.Value();

                    LoadKeyInfo();
                    if (!keyInfoParsed.IsAesGcmPresent)
                        throw new InvalidOperationException("No AES-GCM key available.");

                    byte[] tag, ciphertext;
                    using (FileStream fs = File.OpenRead(dataPathArg.Value))
                    {
                        BinaryReader br = new BinaryReader(fs);
                        tag = br.ReadBytes(16);
                        ciphertext = br.ReadBytes((int)(fs.Length - tag.Length));
                    }

                    using AesGcmCryptor aes = new AesGcmCryptor(keyInfoParsed.AesGcmKey, keyInfoParsed.AesGcmIv);
                    byte[] aesData = aes.Decrypt(ciphertext, tag);

                    File.WriteAllBytes(dataPathArg.Value, aesData);
                });
            });

            app.Command("aesenc", config =>
            {
                config.FullName = "Perform AES-GCM encryption";
                config.Description = "Performs AES-GCM encryption on a file.";

                var configFilePathOpt = config.Option("--config|-c <key-file>", "Path to key file", CommandOptionType.SingleValue);
                configFilePathOpt.Accepts().ExistingFile();
                var dataPathArg = config.Argument("data-path", "Path to file to process").IsRequired();
                dataPathArg.Accepts().ExistingFile();
                config.HelpOption();

                config.OnExecute(() =>
                {
                    if (configFilePathOpt.HasValue())
                        configFilePath = configFilePathOpt.Value();

                    LoadKeyInfo();
                    if (!keyInfoParsed.IsAesGcmPresent)
                        throw new InvalidOperationException("No AES-GCM key available.");

                    byte[] plaintext = File.ReadAllBytes(dataPathArg.Value);

                    using AesGcmCryptor aes = new AesGcmCryptor(keyInfoParsed.AesGcmKey, keyInfoParsed.AesGcmIv);
                    byte[] tag;
                    byte[] aesData = aes.Encrypt(plaintext, out tag);

                    using FileStream fs = File.Create(dataPathArg.Value);
                    fs.Write(tag);
                    fs.Write(aesData);
                });
            });

            app.VersionOptionFromAssemblyAttributes(System.Reflection.Assembly.GetExecutingAssembly());
            app.HelpOption();

            app.OnExecute(() =>
            {
                app.ShowHelp();
                return 1;
            });

            try
            {
                return app.Execute(args);
            }
            catch (CommandParsingException ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 1;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error while processing: {0}", ex);
                return -1;
            }
        }

        static void LoadKeyInfo()
        {
            var keyInfo = JsonSerializer.Deserialize<KeyInfo>(File.ReadAllText(configFilePath));
            keyInfoParsed = keyInfo.Parse();
        }

        static void PadStreamToLength(Stream stream, long length)
        {
            byte[] buffer = new byte[16];
            for (int i = 0; i < buffer.Length; ++i)
                buffer[i] = 0xff;

            stream.Seek(0, SeekOrigin.End);
            while (stream.Length < length)
            {
                stream.Write(buffer, 0, (int)Math.Min(buffer.Length, length - stream.Length));
            }
        }
    }
}
