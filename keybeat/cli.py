import sys
import datetime
from dateutil import tz
import argparse
from . import create_proof, proof_is_valid, decrypt_proof, get_time_for_proof_packet, KeybeatError, KEYBEAT_ARMOURED_HEADER, KEYBEAT_ARMOURED_FOOTER

def main():
    eprint = lambda s: sys.stderr.write(s + "\n")

    def read_input_from_stdin_or_string(arg):
        # If the argument is '-', read from stdin, otherwise treat it as a string
        if arg == '-':
            return sys.stdin.read().strip()
        else:
            return arg

    parser = argparse.ArgumentParser(description="Keybeat CLI")
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # Sub-parser for creating a new proof-of-life
    create_parser = subparsers.add_parser("create", help="Create a new proof-of-life")
    create_parser.add_argument("-s", "--stripped", action="store_true", help="Remove headers and just return base64")
    create_parser.add_argument("-m", "--message", help="Message to attach to the proof")

    # Sub-parser for validating a proof-of-life
    validate_parser = subparsers.add_parser("validate", help="Validate a proof-of-life")
    validate_parser.add_argument("proof_of_life_string", help="Proof-of-life string", type=read_input_from_stdin_or_string)
    validate_parser.add_argument("-a", "--max-age", type=int, help="Maximum age in seconds", required=True)
    validate_parser.add_argument("-p", "--public-key-file", help="Public key file")

    # Sub-parser for getting the time of a proof-of-life
    get_time_parser = subparsers.add_parser("get-time", help="Get the time of a proof-of-life")
    get_time_parser.add_argument("proof_of_life_string", help="Proof-of-life string", type=read_input_from_stdin_or_string)
    get_time_parser.add_argument("-p", "--public-key-file", help="Public key file")

    get_msg_parser = subparsers.add_parser("get-msg", help="Get the message attached to a proof-of-life")
    get_msg_parser.add_argument("proof_of_life_string", help="Proof-of-lift string", type=read_input_from_stdin_or_string)
    get_msg_parser.add_argument("-p", "--public-key-file", help="Public key file")

    args = parser.parse_args()

    if args.command == "create":
        eprint("Fetching latest Bitcoin block as proof-of-life challenge...")
        proof = create_proof(args.message or "")
        if args.stripped:
            print(proof)
        else:
            print(KEYBEAT_ARMOURED_HEADER)
            print(proof)
            print(KEYBEAT_ARMOURED_FOOTER)
    elif args.command == "validate":
        if proof_is_valid(args.proof_of_life_string, args.max_age, args.public_key_file):
            eprint("Proof valid.")
        else:
            eprint("Proof invalid.")
            sys.exit(1)
    elif args.command == "get-time":
        try:
            proof_packet = decrypt_proof(args.proof_of_life_string, args.public_key_file)
            secs_since_epoch = get_time_for_proof_packet(proof_packet)
            utc_time = datetime.datetime.utcfromtimestamp(secs_since_epoch)
            local_tz = tz.tzlocal()
            local_time = utc_time.replace(tzinfo=tz.tzutc()).astimezone(local_tz)

            print(local_time)
        except KeybeatError as e:
            print(f"Error occurred: {e}")
    elif args.command == "get-msg":
        try:
            proof_packet = decrypt_proof(args.proof_of_life_string, args.public_key_file)

            print(proof_packet["message"])
        except KeybeatError as e:
            print(f"Error occurred: {e}")
