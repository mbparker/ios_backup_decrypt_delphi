# ios_backup_decrypt_delphi
iOS password protected backup decryption for Delphi

Complilation Dependencies
https://github.com/mbparker/tools_for_delphi
https://github.com/mbparker/plist_delphi
https://github.com/mbparker/sqlite3_delphi
https://github.com/Xor-el/CryptoLib4Pascal
https://github.com/Xor-el/HashLib4Pascal
https://github.com/Xor-el/SimpleBaseLib4Pascal
https://github.com/paolo-rossi/delphi-neon

Environment Variables for compile time dependencies
TOOLSFORDELPHI_SRC = path to local clone of https://github.com/mbparker/tools_for_delphi/tree/main/src
PLISTDELPHI_SRC = path to local clone of https://github.com/mbparker/plist_delphi/tree/main/src
SQLITE3DELPHI_SRC = path to local clone of https://github.com/mbparker/sqlite3_delphi/tree/main/src
HASHLIB_SRC = path to local clone of https://github.com/Xor-el/HashLib4Pascal/tree/master/HashLib/src
SIMPLEBASELIB_SRC = path to local clone of https://github.com/Xor-el/SimpleBaseLib4Pascal/tree/master/SimpleBaseLib/src
CRYPTOLIB_SRC = path to local clone of https://github.com/Xor-el/CryptoLib4Pascal/tree/master/CryptoLib/src
NEONJSON_SRC = path to local clone of https://github.com/paolo-rossi/delphi-neon/tree/master/Source

Runtime Dependencies
https://github.com/mbparker/sqlite3_delphi/blob/main/bin/win32/sqlite3.dll
https://github.com/mbparker/plist_delphi/blob/main/bin/win32/libplist-2.0.dll
