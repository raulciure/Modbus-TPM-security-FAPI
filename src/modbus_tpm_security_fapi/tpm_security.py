import warnings
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings(
    "ignore",
    category=CryptographyDeprecationWarning,
)

from tpm2_pytss import FAPI, TSS2_Exception
from Crypto.Hash import SHA256
import os

MULTI_PROFILE_FLAG = True   # Set whether current machine has multiple TPM profiles provisioned

DEFAULT_PROFILE = "rsa"
MAIN_PATH = "HS/SRK"
RSA_PROFILE_HIERARCHY = "P_RSA2048SHA256-SRK81000100"
# RSA_PROFILE_HIERARCHY = "P_RSA2048SHA256"
ECC_PROFILE_HIERARCHY = "P_ECCP256SHA256"


def _get_fapi(profile : str = DEFAULT_PROFILE) -> FAPI:
    profiles = {
        "ecc" : "/usr/local/etc/tpm2-tss/fapi-config-ecc.json",
        "rsa" : "/usr/local/etc/tpm2-tss/fapi-config-rsa.json",
    }

    if profile not in profiles:
        raise ValueError("Provided profile is incorrect!")

    os.environ["TSS2_FAPICONF"] = profiles[profile]

    return FAPI()


def _get_profile_hierarchy(profile : str = DEFAULT_PROFILE) -> str:
    profiles = {
        "ecc" : ECC_PROFILE_HIERARCHY,
        "rsa" : RSA_PROFILE_HIERARCHY,
    }

    if profile not in profiles:
        raise ValueError("Provided profile is incorrect!")
    
    return profiles[profile]


def build_tpm_path(*, profile : str = DEFAULT_PROFILE, relative_path : str = "", obj_name : str = ""):
    if '/' in obj_name:     # If tpm_obj_name includes a relative path
        raise ValueError("tpm_obj_name cannot contain relative path! Use path parameter")
    
    if MULTI_PROFILE_FLAG is True:  # Return path containing profile name
        return os.path.join("/", _get_profile_hierarchy(profile).strip("/"), MAIN_PATH.strip("/"), relative_path.strip("/"), obj_name.strip("/"))
    else:                           # Return path without profile name
        return os.path.join("/", MAIN_PATH.strip("/"), relative_path.strip("/"), obj_name.strip("/"))
        

def get_obj_tpm_path(tpm_obj_name : str) -> str:
    tpm_obj_name = tpm_obj_name.strip("/")
    fapi_list = get_fapi_list(build_tpm_path())     # Get fapi objects under the current profile's MAIN_PATH (defined above)
    try:
        elem = next(obj for obj in fapi_list if obj.endswith(tpm_obj_name))
        return elem
    except StopIteration:
        raise ValueError("tpm_obj_name not found in FAPI!")
    

# def auth_callback(path, description, flags) -> (bytes | str):
#     if path == "/HS/SRK/msg_key":
#         return str("raul")
#     return ""


def get_fapi_list(search_path : str | None = None):
    with _get_fapi() as fapi:
        return fapi.list(search_path)

    
def delete_obj(full_path : str, profile : str = DEFAULT_PROFILE):
    with _get_fapi(profile) as fapi:
        try:
            # fapi.set_auth_callback(auth_callback)
            fapi.delete(full_path)
        except TSS2_Exception:
            raise RuntimeError("fapi.delete error!")
        

def create_key(relative_path : str, *, profile : str = DEFAULT_PROFILE, key_type = "decrypt,noda") -> bool:
    if os.getuid() == 0 and "system" not in key_type:   # If running as root without using the system keystore
        raise PermissionError("Should not run as root (sudo) without using system keystore!")

    with _get_fapi(profile) as fapi:
        full_path = build_tpm_path(profile=profile, relative_path=relative_path)
        # Try to create key if it doesn't already exists
        try:
            print("Creating new TPM key.....", end=" ")
            fapi.create_key(full_path, type_=key_type)
            print()
            return True
        except TSS2_Exception as e:
            if e.rc.FAPI_RC_PATH_ALREADY_EXISTS:
                print("Key already exists at the specified path! Key creation FAILED!")
                return False
            else:
                raise RuntimeError("TpmSigner.create_key generic exception!")
            

def get_random(n_bytes : int, profile : str = DEFAULT_PROFILE):
    with _get_fapi(profile) as fapi:
        try:
            return fapi.get_random(n_bytes)
        except TSS2_Exception:
            raise RuntimeError("fapi.get_random error!")


class TpmSigner:
    __full_path : str
    __relative_path : str
    __profile : str

    def __init__(self, tpm_obj_name : str, path : str = "", profile : str = DEFAULT_PROFILE) -> None:
        """
        Create a new TpmSigner object.

        Parameters
        ----------
        tpm_obj_name : str
            The name of the object to be created

        path : str
            The (relative) path of the object.
            Full path is always under /HS/SRK.

        profile : str ("ecc" | "rsa")
            The crypto profile to be used for this object.
            Defaults to RSA TPM profile.
        """

        if tpm_obj_name == "":
            raise ValueError("tpm_obj_name cannot be empty string!")
        
        self.__profile = profile
        self.__relative_path = os.path.join(path.strip("/"), tpm_obj_name)
        self.__full_path = build_tpm_path(profile=self.__profile, relative_path=path, obj_name=tpm_obj_name)
        

    def get_key_path(self):
        return self.__full_path
    
    def get_key_relative_path(self):
        return self.__relative_path
    
    def get_key_profile(self):
        return self.__profile

    def create_key(self, *, system_key : bool = False) -> bool:
        key_type = "sign,noda"
        if system_key is True:
            key_type = "system," + key_type
        return create_key(self.__relative_path, profile=self.__profile, key_type=key_type)

    def sign_hash(self, digest : bytes) -> tuple[bytes, str, str]:
        """
        Sign the received digest.

        Parameters
        ----------
        digest : bytes
            The digest to be signed

        Raises
        ------
        RuntimeError
            If there was an unexpected TPM error.
        
        Returns
        ------
        tuple[bytes, str, str]
            A tuple containing (signature (DER), public key (PEM), certificate (PEM))
        """
        
        with _get_fapi(self.__profile) as fapi:
            try:
                signature, pub_key, certificate = fapi.sign(self.__full_path, digest)
                if isinstance(pub_key, bytes):
                    pub_key = pub_key.decode()
                if isinstance(certificate, bytes):
                    certificate = certificate.decode()
                return (signature, pub_key, certificate)
            except TSS2_Exception:
                raise RuntimeError("TpmSigner.sign exception!")

    def verify_hash(self, digest : bytes, signature : bytes) -> bool:
        with _get_fapi(self.__profile) as fapi:
            try:
                fapi.verify_signature(self.__full_path, digest, signature)
            except TSS2_Exception as e:
                if e.rc.FAPI_RC_SIGNATURE_VERIFICATION_FAILED:
                    print("*** Signature invalid! ***")
                    return False
                raise RuntimeError("TpmSigner.verify generic exception!")
            return True
        
    def sign_data(self, data : bytes | str) -> tuple[bytes, str, str]:
        """
        Sign the received data.

        Parameters
        ----------
        data : bytes
            The data to be signed.
            The hash digest of the data will be the one actually signed.

        Raises
        ------
        RuntimeError
            If there was an unexpected TPM error.
        
        Returns
        ------
        tuple[bytes, str, str]
            A tuple containing (signature (DER), public key (PEM), certificate (PEM))
        """

        if data == "":
            raise ValueError("data cannot be empty string")
        if isinstance(data, str):
            data = data.encode()

        data_hash = SHA256.new(data).digest()

        return self.sign_hash(data_hash)
        
    def delete_key(self):
        """
        Deletes from the TPM the key referenced by this instance.
        """

        delete_obj(self.__full_path, self.__profile)


class TpmSealer:
    __full_path : str
    __relative_path : str
    __profile : str

    def __init__(self, tpm_obj_name : str, path : str = "", profile : str = DEFAULT_PROFILE) -> None:
        """
        Create a new TpmSealer object.

        Parameters
        ----------
        tpm_obj_name : str
            The name of the object to be created

        path : str
            The (relative) path of the object.
            Full path is always under /HS/SRK.

        profile : str ("ecc" | "rsa")
            The crypto profile to be used for this object.
            Defaults to RSA TPM profile.

        system_seal : bool
            Determines whether this seal will be created as a system seal
            Defaults to False
        """

        if tpm_obj_name == "":
            raise ValueError("tpm_obj_name cannot be empty string!")
        
        self.__profile = profile
        self.__relative_path = os.path.join(path.strip("/"), tpm_obj_name)
        self.__full_path = os.path.join("/", _get_profile_hierarchy(self.__profile).strip("/"), MAIN_PATH, self.__relative_path)

    def seal(self, data : bytes | str, system_seal = False) -> bool:
        if os.getuid() == 0 and system_seal is False:   # If running as root without using the system keystore
            raise PermissionError("Should not run as root (sudo) without using system keystore!")
        
        with _get_fapi(self.__profile) as fapi:
            seal_type_arg = None
            if system_seal is True:
                seal_type_arg = "system"
            try:
                fapi.create_seal(self.__full_path, data, type_=seal_type_arg)
                return True
            except TSS2_Exception as e:
                if e.rc.FAPI_RC_PATH_ALREADY_EXISTS:
                    print("*** Path or name already exists! ***")
                    return False
                raise RuntimeError("TpmSealer.seal generic error!")

    def unseal(self):
        with _get_fapi(self.__profile) as fapi:
            try:
                return fapi.unseal(self.__full_path)
            except TSS2_Exception:
                raise RuntimeError("TpmSealer.unseal error!")
            
    def link_with_seal(self, data : bytes | str, system_seal = False):
        if data == "":
            raise ValueError("data cannot be empty string")
        if isinstance(data, str):
            data = data.encode()

        data_hash = SHA256.new(data).digest()

        return self.seal(data_hash, system_seal)
            
    def verify_with_seal(self, data : bytes | str) -> bool:
        if data == "":
            raise ValueError("data cannot be empty string")
        if isinstance(data, str):
            data = data.encode()
        
        data_hash = SHA256.new(data).digest()
        sealed_hash = self.unseal()

        if data_hash == sealed_hash:
            return True
        return False
            
    def delete_seal(self):
        """
        Deletes from the TPM the seal referenced by this instance.
        """

        delete_obj(self.__full_path, self.__profile)
