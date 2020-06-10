# CrypGen

CrypGen is a random password generator, password strength checker, and a message-encryptor accumulated in one application.

You can use CrypGen to:-

1.) Generate multiple strong passwords containing random characters at once.

2.) Check how secure your password is, accomplished using the [zxcvbn](https://github.com/dropbox/zxcvbn) password cracker estimator by DropBox.

3.) Encrypt a message using the One-Time-Pad(OTP) encryption technique.

# How to run:-

Option 1.) You can download CrypGen directly from the release and run the application CrypGen.exe inside the 'build' folder.

Option 2.) You can also run CrypGen using python. First, you will need to install some external modules that don't come pre-installed with python. These modules are:-
- zxcvbn
- pyperclip

Run the commands below to install them using 'pip':-

pip install zxcvbn pyperclip

Then, clone/download the repository which contains the source code and simply run the script using:-

python CrypGen.py

# How to encrypt/decrypt:-

- Folder 'otp'(automatically created on OTP generation, if it doesn't exist):-
This folder will contain all the OTPs that you generate. All OTPs are stored in the format: otp-<filename provided>.
You just have to type the name of the OTP file while creating a OTP and 'otp-' will automatically be attached as prefix. For example:-
if you provided the name 'test', an OTP file named 'otp-test' is created inside the folder 'otp'. Please keep the OTP File that you wish to use inside CrypGen in this folder only otherwise it won't be detected.

- Folder 'encrypted'(automatically created on Encrypting a message, if it doesn't exist):-
This folder will be automatically created (if it doesn't exist) on Encrypting a message and it will contain all the encrypted files that are generated. CrypGen uses the OTP file specified by you to encrypt the message that you typed and saves the encrypted message as a file in this 'encrypted' folder with the filename that you provided. Please keep the encrypted file that you wish to use inside CrypGen in this folder only otherwise it won't be detected.

- To decrypt an encrypted file, the encrypted file MUST be inside 'encrpyted' folder and similarly, the OTP file should also be inside 'otp' folder otherwise they won't be detected. Decrypted message from the file is displayed in a new window.

# IMPORTANT CONSIDERATIONS

- Please type your message that has to be encrypted in lowercase letters as encryption only for lowercase letters is supported as of now.

- The OTP File used to encrypt a message is the only OTP File that can be used to decrypt the file that contains that encrypted message. So, to decrypt an encrypted file, you must provide the same OTP File that was used to encrypt the message in the first place.

- The OTP Encryption Technique is quite simple but nearly unbreakable as long as you keep the OTPs safe. You can send the encrypted file to someone via  e-mail, SMS, etc. but remember to decrpyt that file, they will have to use the same OTP that you used to encrypt the message. You SHOULD NOT send the OTP File electronically too as this is insecure. The best way would be to transfer it via safer routes like pendrive, etc. REMEMBER that your encrypted file is secure only if the OTP for that file is kept secure.

- Length of your message CANNOT be longer than the length of your OTP Sheet. An option is provided while generating OTP to mention the expected length of your message and it is set to 2000 by default. If unsure about message length, just use a higher enough number just to make sure that your message length doesn't excede the OTP Sheet Length.

- Generating too many long passwords may cause the program to slow down or even crash in some cases.

# Examples

- Generating Random Passwords

![](build/img/example1.jpg)


- Checking Password Strength

![](build/img/example2.jpg)


- Encrypting a Message

![](build/img/example3.jpg)


# Background
CrypGen was written in python 3.8.3 and support for older python versions is not guaranteed. It has been tested to run on Windows 10 but most probably won't
run on other operating systems. The exe application in the release was created using [cx-Freeze](https://pypi.org/project/cx-Freeze/).