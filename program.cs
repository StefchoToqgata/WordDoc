// Program.cs
#pragma warning disable SYSLIB0021
#pragma warning disable SYSLIB0022
#nullable disable
#nullable enable annotations
using System;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows.Forms;
using SecureWordEncryptor;
using System.Reflection;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography.Pkcs;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq.Expressions;
using System.Text.Json;
using Timer = System.Windows.Forms.Timer;
using MethodInvoker = System.Windows.Forms.MethodInvoker;
using System.Xml;
using System.Security.Policy;
using System.Collections.Generic;
using Microsoft.Win32;
using Windows.UI.ApplicationSettings;
using System.Runtime.CompilerServices;


#pragma warning disable CS0162 // Dereference of a possibly null reference.
#pragma warning disable SYSLIB0001

namespace SecureWordEncryptor
{
	// ────────────────────────────────────────────────────────────
	// SettingsData + SettingsManager (DPAPI‐protected, appended to EXE)
	// ────────────────────────────────────────────────────────────


	[DataContract]
	public class SettingsData
	{
		[DataMember] public string PendingRegistrationData = "";
		[DataMember] public string LastUsedExtension = "";
		[DataMember] public int FailedPasswordCount = 0;
		[DataMember] public DateTime? LockoutUntil = null;
		[DataMember] public string EncryptionKeyBase64 = "";
		public byte[] FileEncryptionKey { get; set; }
	}

	public static class AntiTaskManager
	{
		[DllImport("user32.dll", SetLastError = true)]
		static extern int ShowWindow(IntPtr hWnd, int nCmdShow);
		const int SW_HIDE = 0, SW_SHOW = 5;

		public static void HideWindow(Form f) => ShowWindow(f.Handle, SW_HIDE);
		public static void ShowWindowAgain(Form f) => ShowWindow(f.Handle, SW_SHOW);
	}

	public sealed class NoCapsBalloonTextBox : TextBox
	{
		private const int EM_SHOWBALLOONTIP = 0x1503;
		private const int EM_HIDEBALLOONTIP = 0x1504;

		protected override void WndProc(ref Message m)
		{
			if (m.Msg == EM_SHOWBALLOONTIP || m.Msg == EM_HIDEBALLOONTIP)
			{
				m.Result = (IntPtr)1;   // swallow Windows’ built-in tip
				return;
			}
			base.WndProc(ref m);
		}
	}

	static class FileAssociation
	{
		const int SHCNE_ASSOCCHANGED = 0x08000000;
		const int SHCNF_IDLIST = 0x0000;

		[DllImport("shell32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		static extern void SHChangeNotify(int wEventId, int uFlags, IntPtr dwItem1, IntPtr dwItem2);

		public static void RegisterEncryptedExtension(
		string extension,
		string progId,
		string description,
		string iconPath,
		string openCommand)
		{
			// 1) .ext → ProgID
			using var extKey = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{extension}");
			extKey.SetValue(null, progId);

			// 2) ProgID → description
			using var progKey = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{progId}");
			progKey.SetValue(null, description);

			// 3) ProgID\DefaultIcon → your .ico
			using var iconKey = Registry.CurrentUser
				.CreateSubKey($@"Software\Classes\{progId}\DefaultIcon");
			iconKey.SetValue(null, iconPath);

			// 4) ProgID\shell\open\command → double-click
			using var cmdKey = Registry.CurrentUser.CreateSubKey(
				$@"Software\Classes\{progId}\shell\open\command");
			cmdKey.SetValue(null, openCommand);

			// 5) tell Explorer to reread icons immediately
			SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, IntPtr.Zero, IntPtr.Zero);
		}
	}

	static class IconProvider
	{
		// Application folder (where custom_icon.ico and encrypted_icon.bin live)
		private static readonly string AppDir = AppDomain.CurrentDomain.BaseDirectory;
		// Raw icon shipped with the app
		private static readonly string RawIcoPath = Path.Combine(AppDir, "custom_icon.ico");
		// Encrypted icon produced at registration time
		private static readonly string EncryptedIcoPath = Path.Combine(AppDir, "encrypted_icon.bin");
		// Where we'll write the decrypted icon for Explorer to use
		private static readonly string TempIcoPath = Path.Combine(Path.GetTempPath(), "swe_icon.ico");

		/// <summary>
		/// Returns the path to the decrypted .ico in %TEMP%.
		/// If that temp file is missing, it will either decrypt encrypted_icon.bin
		/// (if present) or copy the raw ICO on first run.
		/// </summary>
		public static string GetIconPath(string masterPassword)
		{
			if (!File.Exists(TempIcoPath))
				ExtractIcon(masterPassword);
			return TempIcoPath;
		}


		private static void ExtractIcon(string masterPassword)
		{
			if (File.Exists(EncryptedIcoPath))
			{
				// Decrypt the encrypted_icon.bin into the temp ICO
				FileCryptoEngine
					.DecryptFileAsync(EncryptedIcoPath, TempIcoPath, masterPassword, null)
					.GetAwaiter().GetResult();
			}
			else if (File.Exists(RawIcoPath))
			{
				// First run: just copy the raw ICO into temp
				File.Copy(RawIcoPath, TempIcoPath, overwrite: true);
			}
			else
			{
				throw new FileNotFoundException(
					"Neither encrypted_icon.bin nor custom_icon.ico was found in the application directory.");
			}
		}
		public static class FileCryptoEngine
		{
			private const byte FormatVersion = 1;
			private const int NonceSize = 12, TagSize = 16, KeySize = 32;
			private const int ChunkSize = 64 * 1024;

			/// <summary>
			/// AES-GCM-256 encrypts the entire file in one shot.
			/// </summary>
			public static async Task<bool> EncryptFileAsync(
				string inputPath,
				string outputPath,
				string unusedPassword,     // no longer used
				Action<int>? progress)
			{
				try
				{
					var key = Convert.FromBase64String(SettingsManager.Current.EncryptionKeyBase64);
					var plaintext = await File.ReadAllBytesAsync(inputPath);
					var nonce = RandomNumberGenerator.GetBytes(NonceSize);
					var ciphertext = new byte[plaintext.Length];
					var tag = new byte[TagSize];
					var aad = Encoding.UTF8.GetBytes(Path.GetFileName(inputPath));

					// ---- AES-GCM encrypt
					using var aes = new AesGcm(key);
					aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);

					// ---- write out: version | nonce | tag | aad-len | aad | ciphertext
					await using var fs = File.OpenWrite(outputPath);
					fs.WriteByte(FormatVersion);
					fs.Write(nonce);
					fs.Write(tag);
					var lenBytes = BitConverter.GetBytes((ushort)aad.Length);
					fs.Write(lenBytes, 0, lenBytes.Length);
					fs.Write(aad);

					int written = 0;
					while (written < ciphertext.Length)
					{
						int toWrite = Math.Min(ChunkSize, ciphertext.Length - written);
						await fs.WriteAsync(ciphertext, written, toWrite);
						written += toWrite;
						progress?.Invoke((int)(written * 100L / ciphertext.Length));
					}

					progress?.Invoke(100);
					return true;
				}
				catch
				{
					return false;
				}
			}




			/// <summary>
			/// AES-GCM-256 decrypts the entire file.
			/// </summary>
			public static async Task<bool> DecryptFileAsync(
				string sourcePath,
				string outputPath,
				string unusedPassword,
				Action<int>? progress)
			{
				try
				{
					var all = await File.ReadAllBytesAsync(sourcePath);
					int pos = 0;

					if (all[pos++] != FormatVersion)
						throw new InvalidDataException("Unknown file format");

					var nonce = all.AsSpan(pos, NonceSize).ToArray(); pos += NonceSize;
					var tag = all.AsSpan(pos, TagSize).ToArray(); pos += TagSize;
					ushort aadLen = BitConverter.ToUInt16(all, pos); pos += 2;
					var aad = all.AsSpan(pos, aadLen).ToArray(); pos += aadLen;
					var ciphertext = all[pos..];

					var key = Convert.FromBase64String(SettingsManager.Current.EncryptionKeyBase64);
					var plaintext = new byte[ciphertext.Length];

					using var aes = new AesGcm(key);
					aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);

					await File.WriteAllBytesAsync(outputPath, plaintext);
					progress?.Invoke(100);
					return true;
				}
				catch
				{
					return false;
				}
			}
		}


		public static partial class SettingsManager
		{
			// 4-byte clear-text header used to recognise the file
			private static readonly byte[] MAGIC = { (byte)'S', (byte)'W', (byte)'E' };
			private const byte SETTINGS_VERSION = 1;

			// wrapped blobs
			private static byte[] _sek,
								  _saltPwd, _noncePwd, _tagPwd, _ctPwd,
								  _saltAns, _nonceAns, _tagAns, _ctAns,
								  _nonceSet, _tagSet, _ctSet;

			private static readonly byte[] Pepper = Encoding.UTF8.GetBytes("Чушково-ВАЛЮ");

			// constants
			const int WRAP_SALT_BYTES = 16, WRAP_NONCE_BYTES = 12, WRAP_TAG_BYTES = 16;
			const int AES_KEY_BYTES = 32;

			// public API
			public static SettingsData Current { get; private set; } = new SettingsData();
			private static string _settingsPath = "";
			private static string _masterPassword = "";

			/// <summary>
			/// Public wrapper so you can call SettingsManager.Save() from anywhere.
			/// </summary>
			public static void Save()
			{
				if (!string.IsNullOrEmpty(_masterPassword))
					Persist(Current, _masterPassword);
			}

			public const string Marker = "SWE_MARKER";
			public static string? TryReadEmbeddedPath(string exePath)
			{
				byte[] bin = File.ReadAllBytes(exePath);
				byte[] markerBytes = Encoding.ASCII.GetBytes(Marker);
				int idx = bin.AsSpan().LastIndexOf(markerBytes);
				if (idx < 0) return null;

				int start = idx + markerBytes.Length;
				int len = BitConverter.ToInt32(bin, start);
				byte[] cipher = bin.AsSpan(start + 4, len).ToArray();
				byte[] plain = ProtectedData.Unprotect(cipher, null, DataProtectionScope.CurrentUser);
				return Encoding.UTF8.GetString(plain);
			}

			private static byte[] Combine(byte[] a, byte[] b)
			{
				var result = new byte[a.Length + b.Length];
				Buffer.BlockCopy(a, 0, result, 0, a.Length);
				Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
				return result;
			}


			private static byte[] DecryptSekWithAnswers(string answers)
			{
				var ansBytes = Encoding.UTF8.GetBytes(answers);
				var ansPeppered = Combine(ansBytes, Pepper);
				using var kdf = new Argon2id(ansPeppered)
				{
					Salt = _saltAns,
					DegreeOfParallelism = Environment.ProcessorCount,
					MemorySize = 256 * 1024,
					Iterations = 3
				};

				byte[] key = kdf.GetBytes(AES_KEY_BYTES);
				CryptographicOperations.ZeroMemory(ansBytes);
				CryptographicOperations.ZeroMemory(ansPeppered);

				var sek = new byte[_ctAns.Length];
				try
				{
					using var aes = new AesGcm(key, WRAP_TAG_BYTES);
					aes.Decrypt(_nonceAns, _ctAns, _tagAns, sek);
					return sek;
				}
				catch (AuthenticationTagMismatchException)
				{
					throw new InvalidOperationException("Невалиден отговор за възстановяване на парола.");
				}
				finally
				{
					CryptographicOperations.ZeroMemory(key);
				}
			}

			public static string? GetSettingsPath()
			{
				return RegistryHelper.ReadSettingsPath();
			}

			/// <summary>
			/// Returns true if the given path exists on disk and looks like one of our encrypted blobs.
			/// </summary>
			public static bool IsSettingsFile(string path)
			{
				return File.Exists(path) && LooksLikeSettingsFile(path);
			}



			public static void ResetPassword(string answers, string newPassword)
			{
				var path = RegistryHelper.ReadSettingsPath();
				if (string.IsNullOrEmpty(path) || !File.Exists(path))
					throw new InvalidOperationException("Settings file not found.");

				var blob = File.ReadAllBytes(path);
				ParseEnvelope(blob);

				byte[] oldSek = DecryptSekWithAnswers(answers);
				var tlv = DecryptWithSek(_nonceSet, _ctSet, _tagSet, oldSek);
				var cfg = DeserializeTLV(tlv);

				_sek = oldSek;
				_masterPassword = newPassword;
				Current = cfg;

				Persist(Current, newPassword);
			}



			/// <summary>
			/// Scan all fixed drives for a file whose header matches our magic + version.
			/// </summary>


			/// <summary>
			/// Recursive but “safe”—if any directory is unreadable we skip it.
			/// </summary>
			private static IEnumerable<string> SafeEnumerateFiles(string path)
			{
				IEnumerable<string> files;
				try { files = Directory.EnumerateFiles(path); }
				catch { yield break; }

				foreach (var f in files)
					yield return f;

				IEnumerable<string> dirs;
				try { dirs = Directory.EnumerateDirectories(path); }
				catch { yield break; }

				foreach (var d in dirs)
					foreach (var f2 in SafeEnumerateFiles(d))
						yield return f2;
			}

			/// <summary>
			/// Same random‐deep‐C:\ traversal as before,
			/// but now 7-char name + 4-char extension.
			/// </summary>
			private static string PickRandomWindowsPath()
			{
				const int MAX_TRIES = 1000;
				const int MIN_DEPTH = 4;      // ← must end up ≥ two folders deep
				const int MAX_DEPTH = 10;

				string root = Path.GetPathRoot(Environment.SystemDirectory)!;   // “C:\”
				using var rng = RandomNumberGenerator.Create();

				for (int attempt = 0; attempt < MAX_TRIES; attempt++)
				{
					string current = root;
					int depth = 0;

					// 1) Walk down between 2 and 10 *existing* non-hidden folders
					for (; depth < MAX_DEPTH; depth++)
					{
						var subs = Directory.EnumerateDirectories(current)
											.Where(d =>
												  (new DirectoryInfo(d).Attributes & FileAttributes.Hidden) == 0)
											.ToArray();
						if (subs.Length == 0) break;

						byte[] buf = new byte[4];
						rng.GetBytes(buf);
						current = subs[BitConverter.ToUInt32(buf, 0) % subs.Length];
					}

					// guarantee “at least two folders” rule
					if (depth < MIN_DEPTH) continue;

					// 2) 7-char file name + 4-char extension (kept unchanged)
					string namePart = RandomString(7);
					string extensionPart = RandomString(4);
					string candidate = Path.Combine(current, $"{namePart}.{extensionPart}");

					// 3) Found a free spot → done (no new folders ever created)
					if (!File.Exists(candidate))
						return candidate;
				}

				throw new InvalidOperationException(
					$"Unable to find a free settings path under {root} after {MAX_TRIES} attempts.");
			}

			private static string RandomString(int len)
			{
				const string pool =
					 "abcdefghijklmnopqrstuvwxyz" +
					"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
					"0123456789";
				var sb = new StringBuilder(len);
				using var rng = RandomNumberGenerator.Create();
				byte[] buf = new byte[1];
				for (int i = 0; i < len; i++)
				{
					rng.GetBytes(buf);
					sb.Append(pool[buf[0] % pool.Length]);
				}
				return sb.ToString();
			}

			public static void Load(string masterPassword)
			{
				Current = Initialize(masterPassword);
				_masterPassword = masterPassword;
			}

			public static byte[] Sek
			{
				get
				{
					if (Current == null)
						throw new InvalidOperationException("Настройките не бяха заредени.");
					return _sek;
				}
			}

			private static SettingsData Initialize(string pwd)
			{
				// read the registry path (may be null or stale)
				string? path = RegistryHelper.ReadSettingsPath();

				// we declare & initialize cfg here so the compiler always sees it assigned
				SettingsData cfg = new SettingsData();
				bool haveSaved =
					!string.IsNullOrEmpty(pwd) &&
					 !string.IsNullOrEmpty(path) &&
					 File.Exists(path) &&
					 LooksLikeSettingsFile(path);

				if (haveSaved)
				{
					try
					{
						// attempt to decrypt the existing settings blob
						_settingsPath = path!;
						var blob = File.ReadAllBytes(_settingsPath);
						ParseEnvelope(blob);
						_sek = DecryptSekWithPassword(pwd);
						var tlv = DecryptWithSek(_nonceSet, _ctSet, _tagSet, _sek);
						cfg = DeserializeTLV(tlv);
					}

					catch (InvalidOperationException ex) when
						  (ex.Message.Contains("парола", StringComparison.OrdinalIgnoreCase))
					{
						throw;
					}

					catch
					{
						haveSaved = false;
					}
				}

				if (!haveSaved)
				{
					// first-run or fallback: pick a fresh random file, new SEK, blank settings
					_settingsPath = PickRandomWindowsPath();
					_sek = RandomNumberGenerator.GetBytes(AES_KEY_BYTES);

					cfg = new SettingsData
					{
						FileEncryptionKey = RandomNumberGenerator.GetBytes(32),
						EncryptionKeyBase64 = Convert.ToBase64String(
											  RandomNumberGenerator.GetBytes(AES_KEY_BYTES))
					};

					Persist(cfg, pwd);
				}

				// finally, if we do have a password, persist under it
				if (!string.IsNullOrEmpty(pwd))
					Persist(cfg, pwd);

				return cfg;
			}


			private static void Persist(SettingsData cfg, string pwd)
			{
				// 1) serialize TLV and wrap under SEK
				var tlv = SerializeTLV(cfg);
				(_nonceSet, _tagSet, _ctSet) = AesGcmWrapRaw(_sek, tlv);

				// 2) wrap SEK under password & security answers
				(_saltPwd, _noncePwd, _tagPwd, _ctPwd) = AesGcmWrap(_sek, pwd);
				var answers = string.IsNullOrWhiteSpace(cfg.PendingRegistrationData)
								? pwd
								: ExtractAnswers(cfg.PendingRegistrationData);
				(_saltAns, _nonceAns, _tagAns, _ctAns) = AesGcmWrap(_sek, answers);

				// 3) assemble the final blob
				var header = MAGIC.Concat(new[] { SETTINGS_VERSION });
				var outBlob = header
					.Concat(_saltPwd).Concat(_noncePwd).Concat(_tagPwd).Concat(_ctPwd)
					.Concat(_saltAns).Concat(_nonceAns).Concat(_tagAns).Concat(_ctAns)
					.Concat(_nonceSet).Concat(_tagSet).Concat(_ctSet)
					.ToArray();

				// ──────────────────────────────────────────────────────────────
				// 4-6) retry until we find a writable location, *then* rotate
				const int MAX_ATTEMPTS = 100;
				for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++)
				{
					string newPath = PickRandomWindowsPath();
					try
					{
						File.WriteAllBytes(newPath, outBlob);                // ← will throw if folder is protected

						// delete the previous blob – only after the new one is on disk
						if (!string.IsNullOrEmpty(_settingsPath) &&
							_settingsPath != newPath &&
							File.Exists(_settingsPath))
						{
							try { File.Delete(_settingsPath); } catch { /* not fatal */ }
						}

						_settingsPath = newPath;
						RegistryHelper.WriteSettingsPath(_settingsPath);
						return;                                              // success
					}
					catch (UnauthorizedAccessException) { /* pick another dir */ }
					catch (IOException) { /* same */ }
				}
				throw new InvalidOperationException("Unable to find a writable location for the settings file.");
			}


			// ── P/Invokes & embedding back into EXE (unchanged) ────────────

			[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
			static extern bool UpdateResource(
					IntPtr hUpdate,
					IntPtr lpType,
					IntPtr lpName,
					ushort wLanguage,
					byte[] lpData,
					uint cbData
				);

			[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
			static extern IntPtr BeginUpdateResource(
				string pFileName,
				bool bDeleteExistingResources
			);

			[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
			static extern bool EndUpdateResource(
				IntPtr hUpdate,
				bool fDiscard
			);


			static IntPtr MAKEINTRESOURCE(int id) => (IntPtr)id;

			// ── helpers (all inside SettingsManager) ─────────────────────
			private static void ParseEnvelope(byte[] blob)
			{
				int pos = 0;
				if (blob.Length < 4 || blob[0] != MAGIC[0] || blob[1] != MAGIC[1] ||
									   blob[2] != MAGIC[2] || blob[3] != SETTINGS_VERSION)
					throw new InvalidDataException("Не валиден файл за настройките.");

				pos = 4;                                // skip header

				_saltPwd = blob.AsSpan(pos, WRAP_SALT_BYTES).ToArray(); pos += WRAP_SALT_BYTES;
				_noncePwd = blob.AsSpan(pos, WRAP_NONCE_BYTES).ToArray(); pos += WRAP_NONCE_BYTES;
				_tagPwd = blob.AsSpan(pos, WRAP_TAG_BYTES).ToArray(); pos += WRAP_TAG_BYTES;
				_ctPwd = blob.AsSpan(pos, AES_KEY_BYTES).ToArray(); pos += AES_KEY_BYTES;

				_saltAns = blob.AsSpan(pos, WRAP_SALT_BYTES).ToArray(); pos += WRAP_SALT_BYTES;
				_nonceAns = blob.AsSpan(pos, WRAP_NONCE_BYTES).ToArray(); pos += WRAP_NONCE_BYTES;
				_tagAns = blob.AsSpan(pos, WRAP_TAG_BYTES).ToArray(); pos += WRAP_TAG_BYTES;
				_ctAns = blob.AsSpan(pos, AES_KEY_BYTES).ToArray(); pos += AES_KEY_BYTES;

				_nonceSet = blob.AsSpan(pos, WRAP_NONCE_BYTES).ToArray(); pos += WRAP_NONCE_BYTES;
				_tagSet = blob.AsSpan(pos, WRAP_TAG_BYTES).ToArray(); pos += WRAP_TAG_BYTES;
				_ctSet = blob[pos..].ToArray();
			}


			private static byte[] DecryptSekWithPassword(string pwd)
			{
				//Парола и Чушковото
				var pwdBytes = Encoding.UTF8.GetBytes(pwd);
				var pwdPeppered = new byte[pwdBytes.Length + Pepper.Length];
				Buffer.BlockCopy(pwdBytes, 0, pwdPeppered, 0, pwdBytes.Length);
				Buffer.BlockCopy(Pepper, 0, pwdPeppered, pwdBytes.Length, Pepper.Length);

				using var kdf = new Argon2id(pwdPeppered)
				{
					Salt = _saltPwd,
					DegreeOfParallelism = Environment.ProcessorCount,
					MemorySize = 256 * 1024,
					Iterations = 3
				};

				byte[] key = kdf.GetBytes(AES_KEY_BYTES);
				CryptographicOperations.ZeroMemory(pwdBytes);
				CryptographicOperations.ZeroMemory(pwdPeppered);

				byte[] sek = new byte[_ctPwd.Length];
				try
				{
					using var aes = new AesGcm(key, WRAP_TAG_BYTES);
					aes.Decrypt(_noncePwd, _ctPwd, _tagPwd, sek);
					return sek;
				}
				catch (AuthenticationTagMismatchException)
				{
					throw new InvalidOperationException("Паролата е грешна.");
				}
				finally
				{
					CryptographicOperations.ZeroMemory(key);
				}
			}


			public static void ChangePassword(string oldPassword, string newPassword)
			{
				// 1) locate & read existing settings blob
				var path = RegistryHelper.ReadSettingsPath();
				if (string.IsNullOrEmpty(path) || !File.Exists(path))
				{
					// first‐time setup: just persist a brand‐new settings file under the new password
					Persist(Current, newPassword);
					return;
				}


				var blob = File.ReadAllBytes(path);
				ParseEnvelope(blob);

				// 2) decrypt SEK under the old password
				byte[] oldSek = DecryptSekWithPassword(oldPassword);

				// 3) decrypt the settings TLV just to verify answers etc.
				var tlv = DecryptWithSek(_nonceSet, _ctSet, _tagSet, oldSek);
				var cfg = DeserializeTLV(tlv);

				// 4) set up for re‐wrapping
				_sek = oldSek;
				_masterPassword = newPassword;
				Current = cfg;

				// 5) persist under the NEW password (and same answers)
				Persist(Current, newPassword);

				// zero out old password bytes
				oldPassword = null!;
			}

			private static byte[] DecryptWithSek(byte[] nonce, byte[] ct,
											 byte[] tag, byte[] sek)
			{
				var pt = new byte[ct.Length];
				using var aes = new AesGcm(sek, WRAP_TAG_BYTES);
				aes.Decrypt(nonce, ct, tag, pt);
				return pt;
			}


			private static (byte[] salt, byte[] nonce, byte[] tag, byte[] ct)
			AesGcmWrap(byte[] sek, string text)
			{
				var salt = RandomNumberGenerator.GetBytes(WRAP_SALT_BYTES);

				// combine text + pepper
				var txtBytes = Encoding.UTF8.GetBytes(text);
				var txtPeppered = new byte[txtBytes.Length + Pepper.Length];
				Buffer.BlockCopy(txtBytes, 0, txtPeppered, 0, txtBytes.Length);
				Buffer.BlockCopy(Pepper, 0, txtPeppered, txtBytes.Length, Pepper.Length);

				using var kdf = new Argon2id(txtPeppered)
				{
					Salt = salt,
					DegreeOfParallelism = Environment.ProcessorCount,
					MemorySize = 256 * 1024,  // 256 MiB
					Iterations = 3
				};
				var key = kdf.GetBytes(AES_KEY_BYTES);

				// zero out intermediate buffers
				CryptographicOperations.ZeroMemory(txtBytes);
				CryptographicOperations.ZeroMemory(txtPeppered);

				var nonce = RandomNumberGenerator.GetBytes(WRAP_NONCE_BYTES);
				var tag = new byte[WRAP_TAG_BYTES];
				var ct = new byte[sek.Length];

				using var aes = new AesGcm(key, WRAP_TAG_BYTES);
				aes.Encrypt(nonce, sek, ct, tag);

				CryptographicOperations.ZeroMemory(key);

				return (salt, nonce, tag, ct);
			}

			private static (byte[] nonce, byte[] tag, byte[] ct)

			AesGcmWrapRaw(byte[] key, byte[] data)
			{
				var nonce = RandomNumberGenerator.GetBytes(WRAP_NONCE_BYTES);
				var tag = new byte[WRAP_TAG_BYTES];
				var ct = new byte[data.Length];
				using var aes = new AesGcm(key, WRAP_TAG_BYTES);
				aes.Encrypt(nonce, data, ct, tag);
				return (nonce, tag, ct);
			}

			private static string ExtractAnswers(string pending)
			{
				if (string.IsNullOrWhiteSpace(pending)) return "";
				var p = pending.Split('|');
				return $"{(p.Length > 2 ? p[2] : "")}|{(p.Length > 4 ? p[4] : "")}";
			}

			private static bool LooksLikeSettingsFile(string path)
			{
				try
				{
					using var fs = File.OpenRead(path);
					Span<byte> hdr = stackalloc byte[4];
					if (fs.Read(hdr) != 4) return false;
					return hdr[0] == MAGIC[0]
						&& hdr[1] == MAGIC[1]
						&& hdr[2] == MAGIC[2]
						&& hdr[3] == SETTINGS_VERSION;
				}
				catch
				{
					return false;
				}
			}

			private static byte[] SerializeTLV(SettingsData s)
			{
				using var ms = new MemoryStream();
				void W(byte tag, byte[] data)
				{
					ms.WriteByte(tag);
					ms.Write(BitConverter.GetBytes((ushort)data.Length), 0, 2);
					ms.Write(data, 0, data.Length);
				}
				W(1, Encoding.UTF8.GetBytes(s.PendingRegistrationData));
				W(2, Encoding.UTF8.GetBytes(s.LastUsedExtension));
				var keyBytes = Convert.FromBase64String(s.EncryptionKeyBase64);
				W(3, keyBytes);
				return ms.ToArray();
			}


			private static SettingsData DeserializeTLV(byte[] blob)
			{
				var s = new SettingsData();
				int i = 0;
				while (i < blob.Length)
				{
					byte tag = blob[i++];
					ushort len = BitConverter.ToUInt16(blob, i); i += 2;
					var data = blob.Skip(i).Take(len).ToArray(); i += len;
					switch (tag)
					{
						case 1: s.PendingRegistrationData = Encoding.UTF8.GetString(data); break;
						case 2: s.LastUsedExtension = Encoding.UTF8.GetString(data); break;
						case 3: s.EncryptionKeyBase64 = Convert.ToBase64String(data); break;  // NEW
					}
				}
				return s;
			}


			public static class RegistryHelper
			{
				private const string BaseKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
				private const string ValueName = "Start_animation";

				public static string? ReadSettingsPath()
				{
					using var key = Registry.CurrentUser.OpenSubKey(BaseKey, writable: false);
					return key?.GetValue(ValueName) as string;
				}
				public static void WriteSettingsPath(string? path)
				{
					using var key = Registry.CurrentUser.CreateSubKey(BaseKey);
					if (string.IsNullOrEmpty(path))
						key.DeleteValue(ValueName, throwOnMissingValue: false);
					else
						key.SetValue(ValueName, path, RegistryValueKind.String);
				}

				private const string LockoutValue = "LockoutUntil";
				private const string ClockGuard = "LastClockSeen";

				public static void UpdateClockGuard()
				{
					using var key = Registry.CurrentUser.CreateSubKey(BaseKey);
					key.SetValue(ClockGuard, DateTime.Now.ToBinary(), RegistryValueKind.QWord);
				}

				public static bool IsClockRolledBack(int toleranceMinutes = 2)
				{
					using var key = Registry.CurrentUser.OpenSubKey(BaseKey);
					if (key == null) { UpdateClockGuard(); return false; }

					if (key.GetValue(ClockGuard) is long bin)
					{
						var lastSeen = DateTime.FromBinary(bin);
						if (DateTime.Now < lastSeen.AddMinutes(-toleranceMinutes))
							return true;
					}

					UpdateClockGuard();
					return false;
				}

				public static void SetLockout(DateTime until)
				{
					using var key = Registry.CurrentUser.CreateSubKey(BaseKey);
					key.SetValue(LockoutValue, until.ToBinary(), RegistryValueKind.QWord);
				}

				public static DateTime? GetLockout()
				{
					using var key = Registry.CurrentUser.OpenSubKey(BaseKey, writable: false);
					if (key == null) return null;
					object? raw = key?.GetValue(LockoutValue);
					if (key == null) return null;

					long ticks = raw switch
					{
						long l => l,                           // REG_QWORD
						int i => i,                           // REG_DWORD
						byte[] b when b.Length == 8 => BitConverter.ToInt64(b, 0), // REG_BINARY(8)
						string s when long.TryParse(s, out var t) => t,                        // string
						_ => 0
					};

					return ticks == 0 ? null : DateTime.FromBinary(ticks);

				}

				static class FileAssociation
				{
					const int SHCNE_ASSOCCHANGED = 0x08000000;
					const int SHCNF_IDLIST = 0x0000;

					[DllImport("shell32.dll", CharSet = CharSet.Auto, SetLastError = true)]
					static extern void SHChangeNotify(int wEventId, int uFlags, IntPtr dwItem1, IntPtr dwItem2);

					public static void RegisterEncryptedExtension(
						string extension,
						string progId,
						string description,
						string iconPath,
						string openCommand)
					{
						// 1) .ext → ProgID
						using var extKey = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{extension}");
						extKey.SetValue(null, progId);

						// 2) ProgID → description
						using var progKey = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{progId}");
						progKey.SetValue(null, description);

						// 3) ProgID\DefaultIcon → your .ico
						using var iconKey = Registry.CurrentUser
							.CreateSubKey($@"Software\Classes\{progId}\DefaultIcon");
						iconKey.SetValue(null, iconPath);

						// 4) ProgID\shell\open\command → double-click
						using var cmdKey = Registry.CurrentUser.CreateSubKey(
							$@"Software\Classes\{progId}\shell\open\command");
						cmdKey.SetValue(null, openCommand);

						// 5) tell Explorer to reread icons immediately
						SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, IntPtr.Zero, IntPtr.Zero);
					}

				}


				static class Program
				{
					[STAThread]
					static void Main()
					{
						Application.EnableVisualStyles();
						Application.SetCompatibleTextRenderingDefault(false);

						// 1) Do we have a registry-recorded settings blob?
						var settingsPath = SettingsManager.GetSettingsPath();
						bool isRegistered = !string.IsNullOrEmpty(settingsPath)
											&& SettingsManager.IsSettingsFile(settingsPath);

						if (isRegistered)
						{
							// 2) Prompt for _real_ master-password (calls SettingsManager.Load)
							using (var login = new PasswordPromptForm())
								if (login.ShowDialog() != DialogResult.OK)
									return;

							// 3) Re-register icon & extension now that Current is loaded
							var masterPwd = SettingsManager.Current.PendingRegistrationData.Split('|')[0];
							var icoPath = IconProvider.GetIconPath(masterPwd);
							FileAssociation.RegisterEncryptedExtension(
								SettingsManager.Current.LastUsedExtension,
								"SecureWordEncryptor.EncryptedDoc",
								"Encrypted Word Document",
								icoPath,
								$"\"{Process.GetCurrentProcess().MainModule!.FileName}\" \"%1\""
							);
						}

						// 4) Launch main UI (MainForm shows registration UI only if !isRegistered)
						Application.Run(new MainForm());
					}




					public class PasswordPromptForm : Form
					{
						NoCapsBalloonTextBox _tb = new NoCapsBalloonTextBox();
						Button _btnOk = new Button { Text = "Отключи" };
						Label _lblError = new Label { ForeColor = Color.Red };
						Label _lblCountdown = new Label { ForeColor = Color.DarkRed };
						Timer _countdownTimer;
						private const int MAX_ATTEMPTS = 5;
						public string Password { get; private set; }

						protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
						{
							if (keyData == (Keys.Alt | Keys.F4))
								return true;                // swallow
							return base.ProcessCmdKey(ref msg, keyData);
						}

						public PasswordPromptForm()
						{
							//-- window chrome
							Text = "Въведи Паролата";
							FormBorderStyle = FormBorderStyle.FixedDialog;
							MaximizeBox = MinimizeBox = false;
							StartPosition = FormStartPosition.CenterScreen;
							Size = new Size(400, 180);

							//-- password textbox
							_tb.Location = new Point(25, 25);
							_tb.Width = 280;
							_tb.PasswordChar = '❉';
							Controls.Add(_tb);

							//-- OK button
							_btnOk.Location = new Point(145, 70);
							_btnOk.Click += OnOkClicked;
							Controls.Add(_btnOk);
							AcceptButton = _btnOk;     // Enter submits

							//-- error label (hidden)
							_lblError.AutoSize = true;
							_lblError.Location = new Point(25, 110);
							_lblError.Visible = false;
							Controls.Add(_lblError);

							//-- countdown label (hidden)
							_lblCountdown.AutoSize = true;
							_lblCountdown.Visible = false;
							_lblCountdown.Location = new Point(25, 110);
							Controls.Add(_lblCountdown);

							// CAPS-LOCK indicator
							UIHelpers.AddCapsLockIndicator(_tb, this);
							Shown += (_, __) => DetectExistingLockout();
						}

						private void DetectExistingLockout()
						{
							if (SettingsManager.RegistryHelper.IsClockRolledBack())
							{
								_lblError.Text = "Часът на компа бе променен. Пак е блокирано.";
								_lblError.Visible = true;
								_tb.Enabled = _btnOk.Enabled = false;
								return;
							}

							DateTime? until = SettingsManager.RegistryHelper.GetLockout();

							if (until is DateTime t && t > DateTime.Now)
								StartCountdown(t);
						}

						void StartCountdown(DateTime until)
						{
							_tb.Enabled = _btnOk.Enabled = false;
							_lblCountdown.Visible = true;
							UpdateCountdown(until);
							_countdownTimer = new Timer { Interval = 1000 };
							_countdownTimer.Tick += (_, __) =>
							{
								var rem = until - DateTime.Now;
								if (rem <= TimeSpan.Zero)
								{
									_countdownTimer.Stop();
									_lblCountdown.Visible = false;
									_tb.Enabled = _btnOk.Enabled = true;
								}

								else
									UpdateCountdown(until);
							};
							_countdownTimer.Start();
						}

						void UpdateCountdown(DateTime until)
						{
							var rem = until - DateTime.Now;
							_lblCountdown.Text = $"Опитай пак след {rem.Minutes}м {rem.Seconds}с";
						}

						void OnOkClicked(object sender, EventArgs e)
						{
							_lblError.Visible = false;


							if (SettingsManager.RegistryHelper.IsClockRolledBack())
							{
								_lblError.Text = "Часат на компа бе променен. Пак е блокирано.";
								_lblError.Visible = true;
								return;
							}

							DateTime? lockout =
								SettingsManager.RegistryHelper.GetLockout()
								?? SettingsManager.Current.LockoutUntil;

							if (lockout is DateTime until && until > DateTime.Now)
							{
								StartCountdown(until);
								return;
							}

							if (string.IsNullOrWhiteSpace(_tb.Text))
							{
								_lblError.Text = "Трябва да въведеш парола";
								_lblError.Visible = true;
								return;
							}
							try
							{
								SettingsManager.Load(_tb.Text);
							}

							catch (InvalidOperationException ex) when (ex.Message.Contains("Парола"))
							{
								var cfg = SettingsManager.Current;

								cfg.FailedPasswordCount++;
								if (SettingsManager.RegistryHelper.GetLockout() is DateTime activeLock &&
									activeLock > DateTime.Now)
								{
									StartCountdown(activeLock);
									return;
								}

								int remaining = MAX_ATTEMPTS - cfg.FailedPasswordCount;

								if (remaining <= 0)
								{
									DateTime lockoutUntil = DateTime.Now.AddHours(72);
									SettingsManager.RegistryHelper.SetLockout(lockoutUntil);
									SettingsManager.RegistryHelper.UpdateClockGuard();

									cfg.LockoutUntil = lockoutUntil;
									cfg.FailedPasswordCount = 0;
									SettingsManager.Save();

									StartCountdown(lockoutUntil);
									return;
								}


								SettingsManager.Save();

								_lblError.Text = remaining == 1
									? "Последен опит!"
									: $"Грешна парола! Остават {remaining} опита.";
								_lblError.Visible = true;
								return;
							}
						}
						public static Task<bool> DecryptFileAsync(
						string srcPath, string outPath, string password, Action<int>? progress)
						{
							try
							{
								progress?.Invoke(0);
								File.Copy(srcPath, outPath, overwrite: true);
								progress?.Invoke(100);
								return Task.FromResult(true);
							}
							catch
							{
								return Task.FromResult(false);
							}
						}

						public static class UIHelpers
						{
							public static void AddCapsLockIndicator(TextBox tb, Control host)
							{
								if (tb == null || host == null) return;

								var lbl = new Label
								{
									Text = "CAPS",
									Font = new Font("Arial", 15, FontStyle.Bold),
									ForeColor = Color.Black,
									AutoSize = true,
									Visible = Control.IsKeyLocked(Keys.CapsLock),
									BackColor = Color.Transparent
								};
								lbl.Location = new Point(
									tb.Right + 5,
									tb.Top + (tb.Height - lbl.Height) / 2);
								host.Controls.Add(lbl);

								void refresh(object _, EventArgs __)
									=> lbl.Visible = Control.IsKeyLocked(Keys.CapsLock);

								tb.Enter += refresh;
								tb.KeyDown += refresh;
								tb.KeyUp += refresh;
								tb.Leave += (_, __) => lbl.Visible = false;
							}
						}
					}


					// ============================================================
					// NoSelectTextBox: prevent selection & suppress CapsLock tip.
					// ============================================================
					public class NoSelectTextBox : TextBox
					{
						const int WM_LBUTTONDBLCLK = 0x0203, WM_SETSEL = 0x00B1;
						const int EM_SHOWBALLOONTIP = 0x1503, EM_HIDEBALLOONTIP = 0x1504;
						protected override void WndProc(ref Message m)
						{
							if (m.Msg == WM_LBUTTONDBLCLK || m.Msg == WM_SETSEL) return;
							if (m.Msg == EM_SHOWBALLOONTIP || m.Msg == EM_HIDEBALLOONTIP) return;
							base.WndProc(ref m);
						}
						protected override void OnDoubleClick(EventArgs e) => SelectionLength = 0;
						protected override void OnMouseDown(MouseEventArgs e) { base.OnMouseDown(e); SelectionLength = 0; }
						protected override void OnMouseUp(MouseEventArgs e) { base.OnMouseUp(e); SelectionLength = 0; }
					}

					// ============================================================
					// NoSelectLabel: prevent double‑click copy.
					// ============================================================

					public class NoSelectLabel : Label
					{
						const int WM_LBUTTONDBLCLK = 0x0203;
						protected override void WndProc(ref Message m)
						{
							if (m.Msg == WM_LBUTTONDBLCLK) return;
							base.WndProc(ref m);
						}
						protected override void OnDoubleClick(EventArgs e) { }
					}

					// ============================================================
					// MainForm: panels, controls, layout, theme toggle, logic.
					// ============================================================

					public class MainForm : Form
					{
						private bool _allowClose = false;

						// Panels
						private Panel registrationPanel, mainMenuPanel, encryptionPanel,
										  decryptionPanel, changePasswordPanel,
										  forgotPasswordPanel, newPasswordPanel;


						// Registration controls
						private NoSelectTextBox txtPassword, txtPasswordConfirm,
												txtAnswer1, txtAnswer2;
						private ComboBox cmbQuestion1, cmbQuestion2;
						private NoSelectLabel lblError;
						private Button btnRegister;

						// Main menu controls
						private Button btnEncrypt, btnDecrypt, btnChangePassword, btnQuit;
						private NoSelectLabel lblMainMenuError;



						// Encryption controls
						private NoSelectTextBox txtEncryptFilePath;
						private Button btnEncryptBrowse, btnEncryptStart, btnEncryptBack;
						private TextBox txtCustomExtension;
						private ProgressBar progressBarEncrypt;
						private NoSelectLabel lblEncryptStatus;

						// Decryption controls

						private NoSelectTextBox txtDecryptFilePath;
						private Button btnDecryptBrowse, btnDecryptStart, btnDecryptBack;
						private ProgressBar progressBarDecrypt;
						private NoSelectLabel lblDecryptStatus;



						// Change Password controls
						private NoSelectLabel lblCPTitle, lblSecQuestion, lblCPMessage;
						private NoSelectTextBox txtOldPassword, txtOldPasswordConfirm,
												  txtSecAnswer, txtSecAnswerConfirm,
												  txtNewPassword, txtNewPasswordConfirm;
						private Button btnCPSubmit, btnForgotPassword, btnCPBack;

						// Forgot Password controls
						private NoSelectLabel lblFPTitle, lblFPQuestion1, lblFPQuestion2, lblFPMessage;
						private NoSelectTextBox txtForgotAnswer1, txtForgotAnswer2;
						private Button btnFPSubmit, btnFPBack;

						// New Password controls
						private NoSelectLabel lblNPTitle, lblNPMessage;
						private NoSelectTextBox txtNPNewPassword, txtNPNewPasswordConfirm;
						private Button btnNPSubmit, btnNPBack;

						// Stored data
						private string _pendingRegistrationData;
						private string _userPassword;
						private string _lastUsedExtension;

						private bool IsStrongPassword(string pwd)
						{
							return pwd.Length >= 12
							&& pwd.Any(char.IsUpper)
							&& pwd.Any(char.IsLower)
							&& pwd.Any(char.IsDigit)
							&& pwd.Any(ch => !char.IsLetterOrDigit(ch));
						}

						private void AddCapsLockIndicator(TextBox tb, Control host)
						{
							if (tb == null || host == null) return;

							var lbl = new Label
							{
								Text = "CAPS",
								Font = new Font("Arial", 15, FontStyle.Bold),
								ForeColor = Color.Black,
								AutoSize = true,
								Visible = Control.IsKeyLocked(Keys.CapsLock),
								BackColor = Color.Transparent,
							};

							lbl.Location = new Point(
								tb.Right + 5,
								tb.Top + (tb.Height - lbl.Height) / 2);

							host.Controls.Add(lbl);

							void refresh(object _, EventArgs __)
								=> lbl.Visible = Control.IsKeyLocked(Keys.CapsLock);

							tb.Enter += refresh;
							tb.KeyDown += refresh;
							tb.KeyUp += refresh;
							tb.Leave += (_, __) => lbl.Visible = false;

						}

						// Remove system menu buttons
						protected override CreateParams CreateParams
						{
							get
							{
								var cp = base.CreateParams;
								const int WS_SYSMENU = 0x80000;
								const int WS_MINIMIZEBOX = 0x20000;
								const int WS_MAXIMIZEBOX = 0x10000;
								cp.Style &= ~(WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX);
								return cp;
							}
						}

						public MainForm()
						{
							// --- basic form chrome ---
							Icon = SystemIcons.Application;
							FormBorderStyle = FormBorderStyle.FixedSingle;
							MaximizeBox = false;
							MinimizeBox = false;
							Text = "Криптиране и декриптиране на Word документи";
							Size = new Size(600, 550);
							StartPosition = FormStartPosition.CenterScreen;
							KeyPreview = true;
							Font = new Font("Arial", 12);

							// prevent Alt+F4 unless _allowClose is set
							FormClosing += (s, e) =>
							{
								if (!_allowClose)
									e.Cancel = true;
							};

							// 1) build each of your seven panels
							CreateRegistrationPanel();
							CreateMainMenuPanel();
							CreateEncryptionPanel();
							CreateDecryptionPanel();
							CreateChangePasswordPanel();
							CreateForgotPasswordPanel();
							CreateNewPasswordPanel();

							// 2) add them all to the form’s Controls collection
							Controls.AddRange(new Control[]
							{
		registrationPanel,
		mainMenuPanel,
		encryptionPanel,
		decryptionPanel,
		changePasswordPanel,
		forgotPasswordPanel,
		newPasswordPanel
							});

							// 3) pick the one panel you want visible on startup
							_pendingRegistrationData = SettingsManager.Current.PendingRegistrationData;
							if (string.IsNullOrEmpty(_pendingRegistrationData))
							{
								// first run → show registration
								ShowPanel(registrationPanel);
							}
							else
							{
								// returning user → restore saved password and show main menu
								_userPassword = _pendingRegistrationData.Split('|')[0];
								ShowPanel(mainMenuPanel);
							}

							// 4) now that all controls exist, wire up your Caps-Lock indicators
							WireCapsIndicators_Registration();
							WireCapsIndicators_ChangePwd();
							WireCapsIndicators_Forgot();
							WireCapsIndicators_NewPwd();
						}



						//public void Log(string message)
						//{
						//string line = $"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}";

						//try
						//		{

						//		}
						//	catch
						//		{
						// Handle any exceptions that occur during logging
						// For example, you could log to a different file or show a message box
						//			MessageBox.Show("Error writing to log file.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
						//		}
						//}


						private void ShowPanel(Panel p)
						{
							registrationPanel.Visible =
							mainMenuPanel.Visible =
							encryptionPanel.Visible =
							decryptionPanel.Visible =
							changePasswordPanel.Visible =
							forgotPasswordPanel.Visible =
							newPasswordPanel.Visible = false;

							if (p == mainMenuPanel)
								lblMainMenuError.Text = "";

							p.Visible = true;
							p.BringToFront();

							if (p == decryptionPanel && !string.IsNullOrEmpty(_pendingRegistrationData))
							{
								var parts = _pendingRegistrationData.Split('|');
								if (parts.Length >= 6 && File.Exists(parts[5]))
									txtDecryptFilePath.Text = parts[5];
							}
						}

						protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
						{
							if (keyData == (Keys.Alt | Keys.F4)) return true;
							return base.ProcessCmdKey(ref msg, keyData);
						}


						private void ForceExit()

						{

							AntiTaskManager.ShowWindowAgain(this);

							Application.ExitThread();

							Environment.Exit(0);

						}


						// === REGISTRATION PANEL ===

						private void CreateRegistrationPanel()
						{
							registrationPanel = new Panel { Size = ClientSize, Location = Point.Empty };

							var lblTitle = new NoSelectLabel
							{
								Text = "Регистрация",
								Font = new Font("Arial", 16, FontStyle.Bold),
								Location = new Point(220, 20),
								AutoSize = true
							};


							var lblPass = new NoSelectLabel { Text = "Парола:", Location = new Point(50, 80), AutoSize = true };
							txtPassword = new NoSelectTextBox { Location = new Point(200, 80), Width = 300, PasswordChar = '❉' };
							var lblPassC = new NoSelectLabel { Text = "Потвърди Парола:", Location = new Point(50, 120), AutoSize = true };
							txtPasswordConfirm = new NoSelectTextBox { Location = new Point(200, 120), Width = 300, PasswordChar = '❉' };

							string[] questions = new[]
							{
						"Какъв е любимият ви детски спомен?",
						"Какво е името на първото ви училище?",
						"Какъв е бащиното име на баща ви?",
						"Какъв е детският ви прякор?"
					};

							var lblQ1 = new NoSelectLabel { Text = "Въпрос 1:", Location = new Point(50, 160), AutoSize = true };
							cmbQuestion1 = new ComboBox { Location = new Point(200, 160), Width = 300, DropDownStyle = ComboBoxStyle.DropDownList };
							cmbQuestion1.Items.AddRange(questions);
							var lblA1 = new NoSelectLabel { Text = "Отговор 1:", Location = new Point(50, 200), AutoSize = true };
							txtAnswer1 = new NoSelectTextBox { Location = new Point(200, 200), Width = 300 };
							var lblQ2 = new NoSelectLabel { Text = "Въпрос 2:", Location = new Point(50, 240), AutoSize = true };
							cmbQuestion2 = new ComboBox { Location = new Point(200, 240), Width = 300, DropDownStyle = ComboBoxStyle.DropDownList };
							cmbQuestion2.Items.AddRange(questions);
							var lblA2 = new NoSelectLabel { Text = "Отговор 2:", Location = new Point(50, 280), AutoSize = true };
							txtAnswer2 = new NoSelectTextBox { Location = new Point(200, 280), Width = 300 };

							btnRegister = new Button
							{
								Text = "Регистриране",
								Location = new Point(230, 340),
								Size = new Size(120, 40),
								Font = new Font("Arial", 12, FontStyle.Regular),
								TextAlign = ContentAlignment.MiddleCenter
							};


							btnRegister.Click += BtnRegister_Click;
							lblError = new NoSelectLabel { Location = new Point(50, 390), ForeColor = Color.Red, AutoSize = true };
							registrationPanel.Controls.AddRange(new Control[]
							{
							lblTitle,
							lblPass,        txtPassword,
							lblPassC,       txtPasswordConfirm,
							lblQ1,          cmbQuestion1,
							lblA1,          txtAnswer1,
							lblQ2,          cmbQuestion2,
							lblA2,          txtAnswer2,
							btnRegister,
							lblError
							});

						}


						private void BtnRegister_Click(object sender, EventArgs e)
						{
							lblError.Text = "";
							if (string.IsNullOrWhiteSpace(txtPassword.Text) ||
								string.IsNullOrWhiteSpace(txtPasswordConfirm.Text) ||
								string.IsNullOrWhiteSpace(txtAnswer1.Text) ||
								string.IsNullOrWhiteSpace(txtAnswer2.Text) ||
								cmbQuestion1.SelectedIndex < 0 ||
								cmbQuestion2.SelectedIndex < 0)
							{
								lblError.Text = "Попълни всичките полета.";
								return;
							}

							if (txtPassword.Text != txtPasswordConfirm.Text)
							{
								lblError.Text = "Паролите не съвпадат.";
								return;
							}

							// Capture the new credentials and security answers
							_userPassword = txtPassword.Text;
							_pendingRegistrationData =
								$"{_userPassword}|{cmbQuestion1.SelectedItem}|{txtAnswer1.Text}|{cmbQuestion2.SelectedItem}|{txtAnswer2.Text}";

							// Initialize SettingsManager (creates fresh SEK on first run)
							SettingsManager.Load(_userPassword);

							// Store the pending registration data and persist in one step
							SettingsManager.Current.PendingRegistrationData = _pendingRegistrationData;
							SettingsManager.Save();

							// Move on to the main menu
							ShowPanel(mainMenuPanel);
						}


						// === MAIN MENU PANEL ===

						private void CreateMainMenuPanel()
						{
							mainMenuPanel = new Panel { Size = ClientSize, Location = Point.Empty };


							var lblTitleMM = new NoSelectLabel

							{
								Text = "Главното Меню",
								Font = new Font("Arial", 16, FontStyle.Bold),
								Location = new Point(220, 20),
								AutoSize = true
							};

							lblMainMenuError = new NoSelectLabel { Location = new Point(50, 70), ForeColor = Color.Red, AutoSize = true };


							btnEncrypt = new Button
							{
								Text = "Криптиране",
								Size = new Size(200, 60),
								Location = new Point(200, 110),
								Font = new Font("Arial", 12, FontStyle.Regular),
								TextAlign = ContentAlignment.MiddleCenter
							};



							btnEncrypt.Click += (s, eArgs) =>
							{
								lblMainMenuError.Text = "";
								ShowPanel(encryptionPanel);
								//Log("Encryption panel opened.");
							};


							btnDecrypt = new Button
							{
								Text = "Декриптиране",
								Size = new Size(200, 60),
								Location = new Point(200, 190),
								Font = new Font("Arial", 12, FontStyle.Regular),
								TextAlign = ContentAlignment.MiddleCenter

							};

							btnDecrypt.Click += (s, eArgs) =>
							{
								lblMainMenuError.Text = "";
								if (string.IsNullOrEmpty(_lastUsedExtension))
									lblMainMenuError.Text = "Не е намерен.";
								else
									ShowPanel(decryptionPanel);
							};



							btnChangePassword = new Button
							{
								Text = "Смяна на паролата",
								Size = new Size(200, 60),
								Location = new Point(200, 270),
								Font = new Font("Arial", 12, FontStyle.Regular),
								TextAlign = ContentAlignment.MiddleCenter
							};

							btnChangePassword.Click += (s, eArgs) =>
							{

								var parts = _pendingRegistrationData.Split('|');

								int idx = (new Random().Next(2) == 0 ? 1 : 2);

								lblSecQuestion.Text = idx == 1
											? "Въпрос: " + parts[1]
											: "Въпрос: " + parts[3];
								txtOldPassword.Text =
										txtOldPasswordConfirm.Text =
										txtSecAnswer.Text =
										txtSecAnswerConfirm.Text;
								txtNewPassword.Text =
										txtNewPasswordConfirm.Text = "";
								lblCPMessage.Text = "";
								ShowPanel(changePasswordPanel);
							};


							btnQuit = new Button
							{
								Text = "Изход",
								Size = new Size(200, 60),
								Location = new Point(200, 350),
								Font = new Font("Arial", 12, FontStyle.Regular),
								TextAlign = ContentAlignment.MiddleCenter
							};



							btnQuit.Click += (s, e) =>
							{
								// --- REGISTRATION PANEL VALIDATION ---
								if (registrationPanel.Visible)
								{
									lblError.Text = "";

									// 1) All fields must be nonempty and questions selected
									if (string.IsNullOrWhiteSpace(txtPassword.Text) ||
										string.IsNullOrWhiteSpace(txtPasswordConfirm.Text) ||
										cmbQuestion1.SelectedIndex < 0 ||
										cmbQuestion2.SelectedIndex < 0 ||
										string.IsNullOrWhiteSpace(txtAnswer1.Text) ||
										string.IsNullOrWhiteSpace(txtAnswer2.Text))
									{
										lblError.Text = "Попълни всичките полета.";
										return;
									}

									// 2) Password vs. confirmation
									if (txtPassword.Text != txtPasswordConfirm.Text)
									{
										lblError.Text = "Паролите не съвпадат.";
										return;
									}

									// Perform registration exactly as in BtnRegister_Click:
									_userPassword = txtPassword.Text;
									_pendingRegistrationData =
										$"{_userPassword}|{cmbQuestion1.SelectedItem}|{txtAnswer1.Text}|{cmbQuestion2.SelectedItem}|{txtAnswer2.Text}";

									SettingsManager.Load(_userPassword);
									SettingsManager.Current.PendingRegistrationData = _pendingRegistrationData;
									SettingsManager.Save();
									// Now fall through to “save & close” below.
								}
								// --- CHANGE-PASSWORD PANEL VALIDATION ---
								else if (changePasswordPanel.Visible)
								{
									lblCPMessage.ForeColor = Color.Red;
									lblCPMessage.Text = "";

									// 1) Old password vs. its confirmation
									if (txtOldPassword.Text != txtOldPasswordConfirm.Text)
									{
										lblCPMessage.Text = "Старите пароли не съвпадат.";
										return;
									}

									// 2) Verify that “old” actually matches the current master password
									if (txtOldPassword.Text != _userPassword)
									{
										lblCPMessage.Text = "Старата парола е грешна.";
										return;
									}

									// 3) Security answer vs. its confirmation
									if (txtSecAnswer.Text != txtSecAnswerConfirm.Text)
									{
										lblCPMessage.Text = "Отговорите не съвпадат.";
										return;
									}

									// 4) Check that the provided answer matches one of the stored answers
									var parts = _pendingRegistrationData.Split('|');
									if (parts.Length < 5 ||
									   (txtSecAnswer.Text != parts[2] && txtSecAnswer.Text != parts[4]))
									{
										lblCPMessage.Text = "Отговорът е грешен.";
										return;
									}

									// 5) New password vs. its confirmation
									if (txtNewPassword.Text != txtNewPasswordConfirm.Text)
									{
										lblCPMessage.Text = "Новата парола не съвпада.";
										return;
									}

									// Perform password change exactly as in BtnCPSubmit_Click:
									try
									{
										SettingsManager.ChangePassword(txtOldPassword.Text, txtNewPassword.Text);

										_userPassword = txtNewPassword.Text;
										parts[0] = _userPassword;
										_pendingRegistrationData = string.Join("|", parts);

										lblCPMessage.ForeColor = Color.Green;
										lblCPMessage.Text = "Паролата бе променена успешно.";

										// Clear all Change-Password textboxes
										foreach (var tb in new TextBox[] {
									txtOldPassword, txtOldPasswordConfirm,
									txtSecAnswer, txtSecAnswerConfirm,
									txtNewPassword, txtNewPasswordConfirm })
										{
											tb.Clear();
										}
									}
									catch (Exception ex)
									{
										lblCPMessage.ForeColor = Color.Red;
										lblCPMessage.Text = "Грешка при смяна на парола: " + ex.Message;
										return;
									}
									// Now fall through to “save & close” below.
								}
								// --- ENCRYPTION PANEL VALIDATION ---
								else if (encryptionPanel.Visible)
								{
									var inPath = txtEncryptFilePath.Text.Trim();
									var ext = txtCustomExtension.Text.Trim();
									lblEncryptStatus.ForeColor = Color.Black;
									lblEncryptStatus.Text = "";

									// 1) Extension must be nonempty
									if (string.IsNullOrEmpty(ext))
									{
										lblEncryptStatus.ForeColor = Color.Red;
										lblEncryptStatus.Text = "Въведи валиден Filename Extension";
										return;
									}

									// 2) Make sure it starts with “.”
									if (!ext.StartsWith("."))
									{
										ext = "." + ext;
										txtCustomExtension.Text = ext;
									}

									// 3) Extension must be at least two chars (e.g. “.x”)
									if (ext.Length < 2)
									{
										lblEncryptStatus.ForeColor = Color.Red;
										lblEncryptStatus.Text = "Напиши filename extension";
										return;
									}

									// 4) The chosen input file must exist
									if (!File.Exists(inPath))
									{
										if (string.IsNullOrWhiteSpace(inPath))
										{
											lblEncryptStatus.Text = "Select a Word Doc first";
											return;
										}
									}
									// If all checks pass, allow closing (but do not auto-encrypt on Quit).
								}
								// --- DECRYPTION PANEL VALIDATION ---
								else if (decryptionPanel.Visible)
								{
									lblDecryptStatus.ForeColor = Color.Black;
									lblDecryptStatus.Text = "";

									// 1) File must exist
									if (!File.Exists(txtDecryptFilePath.Text))
									{
										lblDecryptStatus.Text = "Файлът не съществува.";
										return;
									}

									// 2) Extension must match the last-used extension
									if (!Path.GetExtension(txtDecryptFilePath.Text)
											  .Equals(_lastUsedExtension, StringComparison.OrdinalIgnoreCase))
									{
										lblDecryptStatus.Text = "Този файл не бе криптиран от моето приложение.";
										return;
									}
									// If both checks pass, allow closing (but do not auto-decrypt on Quit).
								}

								// --- FALLBACK: ORIGINAL “SAVE / ROTATE SETTINGS & CLOSE” LOGIC ---
								try
								{
									var cfg = SettingsManager.Current;
									bool dirty = false;
									if (cfg.PendingRegistrationData == null)
									{
										cfg.PendingRegistrationData = "";
										dirty = true;
									}
									if (string.IsNullOrEmpty(cfg.LastUsedExtension))
									{
										cfg.LastUsedExtension = ".encdoc";
										dirty = true;
									}
									if (dirty)
										SettingsManager.Save();
								}
								catch
								{
									// Even on error, try to save minimal defaults
									SettingsManager.Save();
								}

								// Finally, allow the form to close and exit.
								_allowClose = true;
								Close();
							};

							mainMenuPanel.Controls.AddRange(new Control[] {
						lblTitleMM,
						lblMainMenuError,
						btnEncrypt,
						btnDecrypt,
						btnChangePassword,
						btnQuit
					});
						}


						// === ENCRYPTION PANEL ===
						private void CreateEncryptionPanel()
						{
							encryptionPanel = new Panel { Size = ClientSize, Location = Point.Empty };
							var lblInstr = new NoSelectLabel
							{
								Text = "Избиране на Word Документ (.doc, .docx):",
								Location = new Point(20, 20),
								AutoSize = true
							};

							txtEncryptFilePath = new NoSelectTextBox { Location = new Point(20, 50), Width = 400, AllowDrop = true };
							txtEncryptFilePath.DragEnter += (s, eArgs) =>
							{
								eArgs.Effect = eArgs.Data.GetDataPresent(DataFormats.FileDrop)
									? DragDropEffects.Copy
									: DragDropEffects.None;
							};


							// Драг &дроп за Word
							txtEncryptFilePath.DragDrop += (s, eArgs) =>
							{
								string[] files = (string[])eArgs.Data.GetData(DataFormats.FileDrop);
								if (files.Length > 0 &&
								   (files[0].EndsWith(".doc", StringComparison.OrdinalIgnoreCase)
									|| files[0].EndsWith(".docx", StringComparison.OrdinalIgnoreCase)))

								{
									txtEncryptFilePath.Text = files[0];
								}
							};

							btnEncryptBrowse = new Button
							{
								Text = "...",
								Location = new Point(430, 48),
								Size = new Size(40, 25),
								Font = new Font("Arial", 12, FontStyle.Regular),
								TextAlign = ContentAlignment.MiddleCenter
							};

							btnEncryptBrowse.Click += (s, eArgs) =>
							{
								using (var ofd = new OpenFileDialog { Filter = "Word Документи (*.doc;*.docx)|*.doc;*.docx" })
								{
									if (ofd.ShowDialog() == DialogResult.OK)
										txtEncryptFilePath.Text = ofd.FileName;
								}
							};


							var lblExt = new NoSelectLabel { Text = "Име на Filename Extension (e.g. .enc):", Location = new Point(20, 90), AutoSize = true };
							txtCustomExtension = new TextBox { Location = new Point(20, 115), Width = 100 };
							progressBarEncrypt = new ProgressBar { Location = new Point(20, 160), Size = new Size(450, 25) };
							lblEncryptStatus = new NoSelectLabel { Text = "Статус: Изчакване", Location = new Point(20, 190), AutoSize = true };
							btnEncryptStart = new Button
							{
								Text = "Криптиране",
								Location = new Point(20, 230),
								Size = new Size(120, 35),
								Font = new Font("Arial", 12, FontStyle.Regular),
								TextAlign = ContentAlignment.MiddleCenter
							};


							btnEncryptStart.Click += async (s, eArgs) =>
							{
								var inPath = txtEncryptFilePath.Text.Trim();
								var ext = txtCustomExtension.Text.Trim();
								var ui = this;

								// ─── Extension validation ──────────────────────────────────────────
								if (string.IsNullOrEmpty(ext))
								{
									lblEncryptStatus.ForeColor = Color.Red;
									lblEncryptStatus.Text = "Въведи валиден Filename Extension";
									return;
								}

								if (!ext.StartsWith("."))
								{
									ext = "." + ext;
									txtCustomExtension.Text = ext;
								}

								if (ext.Length < 2)
								{
									lblEncryptStatus.ForeColor = Color.Red;
									lblEncryptStatus.Text = "Напиши filename extension";
									return;
								}

								if (!File.Exists(inPath))
								{
									if (string.IsNullOrWhiteSpace(inPath))
									{
										lblEncryptStatus.Text = "Select a Word Doc first";
										return;
									}
								}

								// ─── Prepare output path & status ─────────────────────────────────
								string outPath = Path.Combine(
									Path.GetDirectoryName(inPath)!,
									Path.GetFileNameWithoutExtension(inPath) + ext);

								lblEncryptStatus.ForeColor = Color.Black;
								lblEncryptStatus.Text = "Криптиране...";

								// ─── Perform encryption ────────────────────────────────────────────
								bool ok = await FileCryptoEngine.EncryptFileAsync(
									inPath,
									outPath,
									_userPassword,
									p =>
									{
										Invoke((Action)(() =>
										{
											progressBarEncrypt.Value = p;
											lblEncryptStatus.Text = $"Encryption: {p}%";
										}));
									});

								if (ok)
								{
									// ─── Update UI + internal state ───────────────────────────────
									lblEncryptStatus.ForeColor = Color.Green;
									lblEncryptStatus.Text = "Криптирането приключи.";
									_lastUsedExtension = ext;

									// Update pending registration data
									var parts = _pendingRegistrationData.Split('|').ToList();
									while (parts.Count < 6) parts.Add("");
									parts[5] = outPath;
									_pendingRegistrationData = string.Join("|", parts);

									// Persist the chosen extension
									SettingsManager.Current.LastUsedExtension = _lastUsedExtension;
									SettingsManager.Save();

									// ─── Register custom icon for this extension ────────────────
									// Ensure the temp icon exists (decrypt/re-create if needed)
									string iconPath = IconProvider.GetIconPath(_userPassword);

									// Map the extension to your ProgID + icon + open command
									FileAssociation.RegisterEncryptedExtension(
										_lastUsedExtension,
										"SecureWordEncryptor.EncryptedDoc",
										"Encrypted Word Document",
										iconPath,
										$"\"{Application.ExecutablePath}\" \"%1\""
									);

									// ─── Securely delete the plaintext file ───────────────────────
									SecureDelete(inPath);
								}
								else
								{
									lblEncryptStatus.ForeColor = Color.Red;
									lblEncryptStatus.Text = "Криптирането е неуспешно.";
								}
							};


							btnEncryptBack = new Button
							{
								Text = "Назад",
								Location = new Point(20, 280),
								Size = new Size(80, 35),
								Font = new Font("Arial", 12, FontStyle.Regular),
								TextAlign = ContentAlignment.MiddleCenter
							};

							btnEncryptBack.Click += (s, eArgs) => ShowPanel(mainMenuPanel);

							encryptionPanel.Controls.AddRange(new Control[]
							{
						lblInstr,
						txtEncryptFilePath, btnEncryptBrowse,
						lblExt, txtCustomExtension,
						progressBarEncrypt, lblEncryptStatus,
						btnEncryptStart, btnEncryptBack
							});
						}

						// === DECRYPTION PANEL ===
						private void CreateDecryptionPanel()
						{
							decryptionPanel = new Panel { Size = ClientSize, Location = Point.Empty };
							var lblInstr = new NoSelectLabel
							{
								Text = "Избери Криптиран файл за декриптиране:",
								Location = new Point(20, 20),
								AutoSize = true
							};

							txtDecryptFilePath = new NoSelectTextBox { Location = new Point(20, 50), Width = 400, AllowDrop = true };
							txtDecryptFilePath.DragEnter += (s, eArgs) =>
							{
								eArgs.Effect = eArgs.Data.GetDataPresent(DataFormats.FileDrop)
									? DragDropEffects.Copy
									: DragDropEffects.None;
							};
							txtDecryptFilePath.DragDrop += (s, eArgs) =>
							{
								string[] files = (string[])eArgs.Data.GetData(DataFormats.FileDrop);

								if (files.Length > 0 &&
								Path.GetExtension(files[0]).Equals(_lastUsedExtension, StringComparison.OrdinalIgnoreCase))
								{
									txtDecryptFilePath.Text = files[0];
								}
							};

							btnDecryptBrowse = new Button
							{
								Text = "...",
								Location = new Point(430, 48),
								Size = new Size(40, 25),
								Font = new Font("Arial", 12, FontStyle.Regular),
								TextAlign = ContentAlignment.MiddleCenter
							};
							btnDecryptBrowse.Click += (s, eArgs) =>
							{
								lblDecryptStatus.Text = "";
								if (string.IsNullOrEmpty(_lastUsedExtension))
								{
									lblDecryptStatus.Text = "Все още не бе създаден криптиран файл.";
									return;
								}

								using (var ofd = new OpenFileDialog { Filter = $"Encrypted Files (*{_lastUsedExtension})|*{_lastUsedExtension}" })
								{
									if (ofd.ShowDialog() == DialogResult.OK)
									{
										if (Path.GetExtension(ofd.FileName).Equals(_lastUsedExtension, StringComparison.OrdinalIgnoreCase))
											txtDecryptFilePath.Text = ofd.FileName;
										else
											lblDecryptStatus.Text = "Extension-ите не съвпадат.";
									}
								}
							};


							progressBarDecrypt = new ProgressBar { Location = new Point(20, 90), Size = new Size(450, 25) };
							lblDecryptStatus = new NoSelectLabel { Text = "Status: В изчакване...", Location = new Point(20, 120), AutoSize = true };

							btnDecryptStart = new Button
							{
								Text = "Декриптиране",
								Location = new Point(20, 160),
								Size = new Size(120, 35),
								Font = new Font("Arial", 12, FontStyle.Regular),
								TextAlign = ContentAlignment.MiddleCenter
							};

							btnDecryptStart.Click += async (s, eArgs) =>
							{
								lblDecryptStatus.ForeColor = Color.Red;
								if (string.IsNullOrWhiteSpace(txtDecryptFilePath.Text))
								{
									lblDecryptStatus.Text = "Избиране на файл за декриптиране.";
									return;
								}

								if (!File.Exists(txtDecryptFilePath.Text))
								{
									lblDecryptStatus.Text = "Файла не съществува.";
									return;
								}

								if (!Path.GetExtension(txtDecryptFilePath.Text).Equals(_lastUsedExtension, StringComparison.OrdinalIgnoreCase))
								{
									lblDecryptStatus.Text = "Този файл не бе криптиран от мойто приложение.";
									return;
								}

								lblDecryptStatus.ForeColor = Color.Black;
								lblDecryptStatus.Text = "Започване на декриптиране...";

								var encryptedPath = txtDecryptFilePath.Text;
								var decryptedPath = Path.Combine(
									Path.GetDirectoryName(encryptedPath)!,
									Path.GetFileNameWithoutExtension(encryptedPath) + ".docx"
								);

								// 2) decrypt into the NEW .docx file
								bool ok = await FileCryptoEngine.DecryptFileAsync(
								encryptedPath, decryptedPath, _userPassword, p =>
								{
									Invoke((MethodInvoker)(() =>
								{
									progressBarDecrypt.Value = p;
									lblDecryptStatus.Text = $"Decrypt: {p}%";
								}));
								});

								if (ok)
								{
									// delete the encrypted .enc
									File.Delete(encryptedPath);

									lblDecryptStatus.ForeColor = Color.Green;
									lblDecryptStatus.Text = "Декриптирането приключи!";
									txtDecryptFilePath.Text = decryptedPath;
								}
								else
								{
									lblDecryptStatus.ForeColor = Color.Red;
									lblDecryptStatus.Text = "Декриптирането е неуспешно.";
								}
							};

							btnDecryptBack = new Button
							{
								Text = "Назад",
								Location = new Point(20, 210),
								Size = new Size(80, 35),
								Font = new Font("Arial", 12, FontStyle.Regular),
								TextAlign = ContentAlignment.MiddleCenter
							};

							btnDecryptBack.Click += (s, eArgs) => ShowPanel(mainMenuPanel);

							decryptionPanel.Controls.AddRange(new Control[]
							{

						lblInstr,
						txtDecryptFilePath, btnDecryptBrowse,
						progressBarDecrypt, lblDecryptStatus,
						btnDecryptStart, btnDecryptBack
							});
						}


						// === CHANGE PASSWORD PANEL ===
						private void CreateChangePasswordPanel()
						{
							changePasswordPanel = new Panel { Size = ClientSize, Location = Point.Empty };
							lblCPTitle = new NoSelectLabel
							{
								Text = "Промяна на парола",
								Font = new Font("Arial", 16, FontStyle.Bold),
								Location = new Point(200, 20),

								AutoSize = true

							};

							lblSecQuestion = new NoSelectLabel
							{
								Text = "Въпрос:",
								Location = new Point(20, 60),
								AutoSize = true,
								MaximumSize = new Size(560, 0)
							};


							var lblOld = new NoSelectLabel { Text = "Стара парола:", Location = new Point(20, 120), AutoSize = true };
							txtOldPassword = new NoSelectTextBox { Location = new Point(235, 120), Width = 250, PasswordChar = '❉' };
							var lblOldC = new NoSelectLabel { Text = "Въведи Старата Парола:", Location = new Point(20, 160), AutoSize = true };
							txtOldPasswordConfirm = new NoSelectTextBox { Location = new Point(235, 160), Width = 250, PasswordChar = '❉' };
							var lblSA = new NoSelectLabel { Text = "Отговор:", Location = new Point(20, 200), AutoSize = true };
							txtSecAnswer = new NoSelectTextBox { Location = new Point(235, 200), Width = 250 };
							var lblSAC = new NoSelectLabel { Text = "Въведи Отговора отово:", Location = new Point(20, 240), AutoSize = true };
							txtSecAnswerConfirm = new NoSelectTextBox { Location = new Point(235, 240), Width = 250 };
							var lblNew = new NoSelectLabel { Text = "Нова парола:", Location = new Point(20, 280), AutoSize = true };
							txtNewPassword = new NoSelectTextBox { Location = new Point(235, 280), Width = 250, PasswordChar = '❉' };
							var lblNewC = new NoSelectLabel { Text = "Въведи новата Парола:", Location = new Point(20, 320), AutoSize = true };
							txtNewPasswordConfirm = new NoSelectTextBox { Location = new Point(235, 320), Width = 250, PasswordChar = '❉' };

							btnCPBack = new Button
							{
								Text = "Назад",
								Location = new Point(80, 380),
								Size = new Size(120, 40),
								Font = new Font("Arial", 12, FontStyle.Regular),
								TextAlign = ContentAlignment.MiddleCenter
							};

							btnCPBack.Click += (s, eArgs) => ShowPanel(mainMenuPanel);

							btnCPSubmit = new Button
							{
								Text = "Промени",
								Location = new Point(220, 380),
								Size = new Size(120, 40),
								Font = new Font("Arial", 12, FontStyle.Regular),
								TextAlign = ContentAlignment.MiddleCenter

							};
							btnCPSubmit.Click += BtnCPSubmit_Click;


							btnForgotPassword = new Button
							{
								Text = "Парола не Помниш",
								Location = new Point(360, 380),
								Size = new Size(160, 40),
								Font = new Font("Arial", 12, FontStyle.Regular),
								TextAlign = ContentAlignment.MiddleCenter
							};

							btnForgotPassword.Click += (s, eArgs) =>
							{
								var parts = _pendingRegistrationData.Split('|');
								lblFPQuestion1.Text = "Въпрос 1: " + parts[1];
								lblFPQuestion2.Text = "Въпрос 2: " + parts[3];
								txtForgotAnswer1.Text = "";
								txtForgotAnswer2.Text = "";
								lblFPMessage.Text = "";
								ShowPanel(forgotPasswordPanel);
							};


							lblCPMessage = new NoSelectLabel
							{
								Location = new Point(20, 430),
								Size = new Size(560, 30),
								ForeColor = Color.Red,
								AutoSize = false
							};

							changePasswordPanel.Controls.AddRange(new Control[]
							{
						lblCPTitle, lblSecQuestion,
						lblOld, txtOldPassword,
						lblOldC, txtOldPasswordConfirm,
						lblSA, txtSecAnswer,
						lblSAC, txtSecAnswerConfirm,
						lblNew, txtNewPassword,
						lblNewC, txtNewPasswordConfirm,
						btnCPBack, btnCPSubmit, btnForgotPassword,
						lblCPMessage
							});
						}


						private void BtnCPSubmit_Click(object sender, EventArgs e)
						{
							lblCPMessage.ForeColor = Color.Red;
							lblCPMessage.Text = "";

							if (txtOldPassword.Text != txtOldPasswordConfirm.Text)
							{
								lblCPMessage.Text = "Старите пароли не съвпат.";
								return;
							}

							if (txtOldPassword.Text != _userPassword)
							{
								lblCPMessage.Text = "Старата парола е грешна.";
								return;
							}

							if (txtSecAnswer.Text != txtSecAnswerConfirm.Text)
							{
								lblCPMessage.Text = "Отговорите не съвпадат.";
								return;
							}


							var parts = _pendingRegistrationData.Split('|');

							if (parts.Length < 5 ||
								(txtSecAnswer.Text != parts[2] && txtSecAnswer.Text != parts[4]))
							{
								lblCPMessage.Text = "Отговора е грешен.";
								return;
							}

							if (txtNewPassword.Text != txtNewPasswordConfirm.Text)
							{
								lblCPMessage.Text = "Новата парола не съвпада.";
								return;
							}

							var newPwd = txtNewPassword.Text;

							try
							{
								// perform the atomic change
								SettingsManager.ChangePassword(txtOldPassword.Text, newPwd);

								// update UI state
								_userPassword = newPwd;
								parts[0] = _userPassword;
								_pendingRegistrationData = string.Join("|", parts);

								lblCPMessage.ForeColor = Color.Green;
								lblCPMessage.Text = "Паролата бе променена успешно.";

								// wipe inputs immediately
								foreach (var tb in new TextBox[] {
								txtOldPassword, txtOldPasswordConfirm,
								txtSecAnswer, txtSecAnswerConfirm,
								txtNewPassword, txtNewPasswordConfirm })
									tb.Clear();
							}
							catch (Exception ex)
							{
								lblCPMessage.ForeColor = Color.Red;
								lblCPMessage.Text = "Грешка при смяна на парола: " + ex.Message;
							}

						}



						// === FORGOT PASSWORD PANEL ===
						private void CreateForgotPasswordPanel()
						{
							forgotPasswordPanel = new Panel { Size = ClientSize, Location = Point.Empty };
							lblFPTitle = new NoSelectLabel
							{
								Text = "Забравена парола",
								Font = new Font("Arial", 16, FontStyle.Bold),
								Location = new Point(200, 20),
								AutoSize = true
							};



							lblFPQuestion1 = new NoSelectLabel
							{
								Location = new Point(20, 80),
								Size = new Size(560, 30),
								Font = new Font("Arial", 12),
								AutoSize = false
							};


							txtForgotAnswer1 = new NoSelectTextBox { Location = new Point(20, 115), Size = new Size(460, 30) };
							lblFPQuestion2 = new NoSelectLabel
							{
								Location = new Point(20, 150),
								Size = new Size(450, 30),
								Font = new Font("Arial", 12),
								AutoSize = false
							};


							txtForgotAnswer2 = new NoSelectTextBox { Location = new Point(20, 185), Size = new Size(460, 30) };

							btnFPBack = new Button
							{
								Text = "Назад",
								Location = new Point(180, 260),
								Size = new Size(120, 40),
								Font = new Font("Arial", 12, FontStyle.Regular),
								TextAlign = ContentAlignment.MiddleCenter
							};


							btnFPBack.Click += (s, eArgs) => ShowPanel(changePasswordPanel);

							btnFPSubmit = new Button
							{
								Text = "Напред",
								Location = new Point(320, 260),
								Size = new Size(120, 40),
								Font = new Font("Arial", 12, FontStyle.Regular),
								TextAlign = ContentAlignment.MiddleCenter
							};

							btnFPSubmit.Click += (s, eArgs) =>
							{
								lblFPMessage.ForeColor = Color.Red;
								lblFPMessage.Text = "";
								var parts = _pendingRegistrationData.Split('|');

								if (txtForgotAnswer1.Text != parts[2] || txtForgotAnswer2.Text != parts[4])
								{
									lblFPMessage.Text = "Един или всички отговори са грешни.";
									return;
								}

								lblFPMessage.ForeColor = Color.Green;
								lblFPMessage.Text = "Отговорите са верни.Пренасочване след 5 секунди.";
								var t = new Timer { Interval = 3000 };

								t.Tick += (sender3, args3) =>
								{
									t.Stop();
									ShowPanel(newPasswordPanel);
								};
								t.Start();
							};

							lblFPMessage = new NoSelectLabel
							{
								Location = new Point(20, 315),
								Size = new Size(560, 30),
								Font = new Font("Arial", 12),
								ForeColor = Color.Red,
								AutoSize = false
							};

							forgotPasswordPanel.Controls.AddRange(new Control[]
							{
						lblFPTitle,
						lblFPQuestion1, txtForgotAnswer1,
						lblFPQuestion2, txtForgotAnswer2,
						btnFPBack, btnFPSubmit,
						lblFPMessage
							});
						}


						// === NEW PASSWORD PANEL ===
						private void CreateNewPasswordPanel()
						{
							newPasswordPanel = new Panel { Size = ClientSize, Location = Point.Empty };

							// Title
							var lblNPTitle = new NoSelectLabel
							{
								Text = "Възстановяване на паролата",
								Font = new Font("Arial", 16, FontStyle.Bold),
								Location = new Point(200, 20),
								AutoSize = true
							};

							// “Enter new password” label + textbox
							var lblNP1 = new NoSelectLabel
							{
								Text = "Нова парола:",
								Location = new Point(50, 100),
								AutoSize = true
							};
							txtNPNewPassword = new NoSelectTextBox
							{
								Location = new Point(250, 100),
								Width = 250,
								PasswordChar = '❉'
							};

							// “Confirm new password” label + textbox
							var lblNP2 = new NoSelectLabel
							{
								Text = "Потвърди парола:",
								Location = new Point(50, 150),
								AutoSize = true
							};
							txtNPNewPasswordConfirm = new NoSelectTextBox
							{
								Location = new Point(250, 150),
								Width = 250,
								PasswordChar = '❉'
							};

							// In-panel message label
							lblNPMessage = new NoSelectLabel
							{
								Location = new Point(50, 190),
								ForeColor = Color.Red,
								AutoSize = true
							};

							// Back button
							btnNPBack = new Button
							{
								Text = "Назад",
								Location = new Point(80, 220),
								Size = new Size(120, 35),
								Font = new Font("Arial", 12),
								TextAlign = ContentAlignment.MiddleCenter
							};
							btnNPBack.Click += (s, e) => ShowPanel(forgotPasswordPanel);

							// Submit button
							btnNPSubmit = new Button
							{
								Text = "Промени",
								Location = new Point(240, 220),
								Size = new Size(120, 35),
								Font = new Font("Arial", 12),
								TextAlign = ContentAlignment.MiddleCenter
							};
							btnNPSubmit.Click += (s, e) =>
							{
								lblNPMessage.ForeColor = Color.Red;
								lblNPMessage.Text = "";

								// Make sure the two entries match
								if (txtNPNewPassword.Text != txtNPNewPasswordConfirm.Text)
								{
									lblNPMessage.Text = "Паролите не съвпадат.";
									return;
								}

								try
								{
									// Reset via security answers (already validated)
									var parts = SettingsManager.Current.PendingRegistrationData.Split('|');
									var answers = $"{parts[2]}|{parts[4]}";
									SettingsManager.ResetPassword(answers, txtNPNewPassword.Text);

									// Success message in-panel
									lblNPMessage.ForeColor = Color.Green;
									lblNPMessage.Text = "Паролата беше сменена успешно. Пренасочване...";

									// After 3 seconds, auto-go back to main menu
									var t = new Timer { Interval = 3000 };
									t.Tick += (ts, te) =>
									{
										t.Stop();
										ShowPanel(mainMenuPanel);
									};
									t.Start();
								}
								catch (Exception ex)
								{
									lblNPMessage.Text = ex.Message;
								}
							};

							newPasswordPanel.Controls.AddRange(new Control[]
							{
							lblNPTitle,
							lblNP1, txtNPNewPassword,
							lblNP2, txtNPNewPasswordConfirm,
							lblNPMessage,
							btnNPBack, btnNPSubmit
							});
						}


						// === SECURE DELETE ===
						private void SecureDelete(string filePath)
						{
							try
							{
								if (!File.Exists(filePath)) return;
								long length = new FileInfo(filePath).Length;
								byte[] buffer = new byte[4096];
								for (int pass = 0; pass < 3; pass++)
								{
									using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
									{
										fs.Position = 0;
										fs.Write(buffer, 0, buffer.Length);
										long remaining = length;
										while (remaining > 0)
										{
											int chunk = (int)Math.Min(buffer.Length, remaining);
											Array.Clear(buffer, 0, chunk);
											fs.Write(buffer, 0, chunk);
											remaining -= chunk;
										}
										fs.Flush();
									}
								}
								File.Delete(filePath);
							}
							catch { }
						}

						//  registration panel textboxes
						private void WireCapsIndicators_Registration()
						{
							foreach (var tb in new[]
								   { txtPassword, txtPasswordConfirm, txtAnswer1, txtAnswer2 })
								AddCapsLockIndicator(tb, registrationPanel);
						}

						//  forgot‑password panel textboxes
						private void WireCapsIndicators_Forgot()
						{
							foreach (var tb in new[]
								   { txtForgotAnswer1, txtForgotAnswer2 })
								AddCapsLockIndicator(tb, forgotPasswordPanel);
						}

						//  new‑password panel textboxes
						private void WireCapsIndicators_NewPwd()
						{
							foreach (var tb in new[]
								   { txtNPNewPassword, txtNPNewPasswordConfirm })
								AddCapsLockIndicator(tb, newPasswordPanel);
						}


						//  change‑password panel textboxes
						private void WireCapsIndicators_ChangePwd()
						{
							foreach (var tb in new[]
								   { txtOldPassword, txtOldPasswordConfirm,
						 txtSecAnswer,    txtSecAnswerConfirm,
						 txtNewPassword,  txtNewPasswordConfirm })
								AddCapsLockIndicator(tb, changePasswordPanel);
						}

						//  call the helpers once, from the MainForm constructor
						//  (add this line just after ShowPanel(registrationPanel); 
						//   WireCapsIndicators_Registration();
						//    WireCapsIndicators_ChangePwd();
						//    WireCapsIndicators_Forgot();
						//     WireCapsIndicators_NewPwd();
						//  and the rest of the panels when they are created
						//dsdadada
					}
				}
			}
		}
	}
}

#pragma warning disable IL3000
#pragma warning disable SYSLIB0001
#pragma warning restore
#pragma warning restore SYSLIB0021
#pragma warning restore SYSLIB0022
