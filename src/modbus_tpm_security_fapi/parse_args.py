import argparse
import os


def parse_args_main(prog_path : str):
    # from src.modbus_tpm_security.gateway.gateway_common import REKEY_TIME
    from src.modbus_tpm_security_fapi.sym_cipher import CipherTypes

    parser = argparse.ArgumentParser(os.path.basename(prog_path))
    parser.add_argument("host", nargs="?", type=str, metavar="HOST_IP", help="Set custom host IP address, as string")
    parser.add_argument("dest", nargs="?", type=str, metavar="PEER_IP", help="Set custom dest (peer) IP address, as string")
    parser.add_argument("--host-ip", type=str, metavar="IP_Addr", help="Set custom host IP, as string")
    parser.add_argument("--dest-ip", type=str, metavar="IP_Addr", help="Set custom dest IP, as string")
    parser.add_argument("--measure-perf", action="store_true", help="Measure performance of the cryptographic operations")
    parser.add_argument("--set-timestamp-tolerance", type=int, default=1, metavar="SECONDS", help="Set custom timestamp tolerance for replay attack resistance, in seconds (default 1)")
    parser.add_argument("--disable-replay-resistance", action="store_true", help="Disable replay attack resistance")
    parser.add_argument("--set-rekey-interval", type=int, default=600, metavar="SECONDS", help="Set custom rekey interval for forward secrecy support, in seconds (default 600)")
    parser.add_argument("--disable-rekeying", action="store_true", help="Disable periodic rekeying and forward secrecy support")
    parser.add_argument("--debug", action="store_true", help="Turn on debugging text in OOP classes")

    parser.add_argument("--set-cipher", type=CipherTypes.get_cipher_index, choices=CipherTypes.get_cipher_list_str(), default="AES_GCM",
                        metavar=CipherTypes.get_cipher_formatted_list(), help="Set symmetric cipher to use (default: AES_GCM)")

    args = parser.parse_args()

    return args


def parse_args_RSA_key_exchange(prog_path : str):
    parser = argparse.ArgumentParser(os.path.basename(prog_path))
    parser.add_argument("host", nargs="?", type=str, metavar="HOST_IP", help="Set custom host IP address, as string")
    parser.add_argument("dest", nargs="?", type=str, metavar="PEER_IP", help="Set custom dest (peer) IP address, as string")
    parser.add_argument("--host-ip", type=str, metavar="IP_Addr", help="Set custom host IP, as string")
    parser.add_argument("--dest-ip", type=str, metavar="IP_Addr", help="Set custom dest IP, as string")

    args = parser.parse_args()

    return args