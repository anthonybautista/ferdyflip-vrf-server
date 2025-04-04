import keys


def main():
    new_account_info = keys.new_account()
    print(f"key: {new_account_info[0]} - account: {new_account_info[1].address}")
    print("obfuscated_key: " + keys.obfuscate_string(new_account_info[0]))


main()
