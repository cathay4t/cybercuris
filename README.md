# CyberCuris -- Linux Password Management GUI Tool in Rust

## Features
 * No plain password been stored to disk.
 * Strictly constrained lifetime of plain password in memory.
 * Kernel panic cannot dump memory holding plain password.
 * Userspace crash core cannot dump memory holding plain password.
 * Use AES-GCM encryption.
 * TODO: Support TOTP

## GUI Usage
 * You need to chose a main password to protect all your passwords.
 * The encrypted keys is stored in `~/.local/share/cybercuris/`. No plain.
 * Type to search, `Esc` to clear search bar. `Esc` again to hide main window.
 * `Enter` to copy password. The password will drop after first paste (e.g.
   Control+V) requested.
 * `killall -s USR1 cybercuris` will lock the password again.
 * Unlocked state only last 4 hours, then enter locked state.

## Workflow
 * Initialization main key if not found
   Generate random 4096 length random key, ask user to input main password
   in GUI/CLI, then store the encrypted key to ~/.local/share/cybercuris/main.key

 * When user store password, use decrypt main.key into MemoryGuard.
   Use this main key to encrypt password and stored to
   ~/.local/share/password/<name>.key

 * When user copy a password, cybercuris request decrypt
   ~/.local/share/cybercuris/main.key.encrypted to get MemoryGuard,
   load the requested encrypted password into memory.

 * CyberCuris notify wayland that it is holding clipboard

 * Upon wayland route the clipboard request to CyberCuris, CyberCuris decrypt
   password into MemoryGuard, reply to requester, drop the MemoryGuard.

## Memory Protection -- `struct MemoryGuard`

 * Use `libc::mlock()` to prevent memory been swap to disk.
 * Upon dropping, set MemoryGuard properties to zero before release.
 * Use `libc::madvise()` with `MADV_DONTDUMP` to prevent core dump store this
   memory.
 * The life time of `MemoryGuard` is strictly constrained, similar to
   MutexGuard.
