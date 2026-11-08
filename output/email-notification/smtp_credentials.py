"""SMTP secrets stored only in the current user's Windows Credential Manager."""
import ctypes
from ctypes import wintypes
import os


class Credential(ctypes.Structure):
    _fields_ = [
        ('Flags', wintypes.DWORD),
        ('Type', wintypes.DWORD),
        ('TargetName', wintypes.LPWSTR),
        ('Comment', wintypes.LPWSTR),
        ('LastWritten', wintypes.FILETIME),
        ('CredentialBlobSize', wintypes.DWORD),
        ('CredentialBlob', ctypes.POINTER(ctypes.c_ubyte)),
        ('Persist', wintypes.DWORD),
        ('AttributeCount', wintypes.DWORD),
        ('Attributes', ctypes.c_void_p),
        ('TargetAlias', wintypes.LPWSTR),
        ('UserName', wintypes.LPWSTR),
    ]


def api():
    if os.name != 'nt':
        raise RuntimeError('Windows Credential Manager requires Windows')
    lib = ctypes.WinDLL('Advapi32.dll', use_last_error=True)
    lib.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                              ctypes.POINTER(ctypes.POINTER(Credential))]
    lib.CredReadW.restype = wintypes.BOOL
    lib.CredWriteW.argtypes = [ctypes.POINTER(Credential), wintypes.DWORD]
    lib.CredWriteW.restype = wintypes.BOOL
    lib.CredFree.argtypes = [ctypes.c_void_p]
    lib.CredFree.restype = None
    return lib


def target(host, username):
    return f'OpenCode-Network/SMTP/{host.lower()}/{username.lower()}'


def read_password(host, username):
    lib = api()
    ptr = ctypes.POINTER(Credential)()
    if not lib.CredReadW(target(host, username), 1, 0, ctypes.byref(ptr)):
        error = ctypes.get_last_error()
        if error == 1168:  # ERROR_NOT_FOUND
            return None
        raise OSError(error, 'Cannot read SMTP credential')
    try:
        return ctypes.string_at(ptr.contents.CredentialBlob,
                                ptr.contents.CredentialBlobSize).decode('utf-16-le')
    finally:
        lib.CredFree(ptr)


def write_password(host, username, password):
    if any(ord(c) < 32 or ord(c) == 127 for c in password):
        raise ValueError('SMTP password must not contain control characters')
    blob = password.encode('utf-16-le')
    if not blob or len(blob) > 2560:
        raise ValueError('Invalid credential length')
    buffer = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
    item = Credential()
    item.Type = 1  # CRED_TYPE_GENERIC
    item.TargetName = target(host, username)
    item.UserName = username
    item.CredentialBlobSize = len(blob)
    item.CredentialBlob = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
    item.Persist = 2  # CRED_PERSIST_LOCAL_MACHINE, scoped to current user
    try:
        if not api().CredWriteW(ctypes.byref(item), 0):
            raise OSError(ctypes.get_last_error(), 'Cannot store SMTP credential')
    finally:
        ctypes.memset(buffer, 0, len(blob))
