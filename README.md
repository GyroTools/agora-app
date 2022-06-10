# agora-app
Agora helper app to download data and execute local tasks

## Download
The latest release of the agora-app can be found [here](https://github.com/GyroTools/agora-app/releases/latest/). Please make sure you choose the correct platform.

## Installation

### Windows
1. Create a folder somewhere in your system, ex.: C:\agora-app.
2. Download the binary and put it into the folder you created. The following assumes that the binary is called agora-app.exe
3. Run an [elevated command prompt](https://docs.microsoft.com/en-us/powershell/scripting/windows-powershell/starting-windows-powershell?view=powershell-7#with-administrative-privileges-run-as-administrator)
4. Register the agora-app:
    ```
    .\agora-app register
    ```
   During the registering process you have to enter the download path, Agora URL and credentials. 
5. Install the agora-app as a service and start it. You can either run the service using the Built-in System Account (recommended) or using a user account.

    Run service using Built-in System Account (under directory created in step 1. from above, ex.: C:\agora-app)

    ```
    cd C:\agora-app
    .\agora-app.exe install
    .\agora-app.exe start
    ```

    Run service using user account (under directory created in step 1. from above, ex.: C:\agora-app)
    You have to enter a valid password for the current user account, because it’s required to start the service by Windows:

    ```
    cd C:\agora-app
    .\agora-app.exe install --user ENTER-YOUR-USERNAME --password ENTER-YOUR-PASSWORD
    .\agora-app.exe start
    ```

#### Windows service and GUI applications
For security reasons a Windows service is not allowed to start an application with a user-interface. This can be a problem if a local Agora-task needs to open a GUI application (e.g. notepad). In that case you will need to run the agora-app as local user in a command prompt:

     ```
     ./agora-app run
     ```

If the app should be started with Windows it can be added to the autostart. 

### Linux
#### Run as service (Recommended)
Running the agora-app as service is the recommended way, but needs root privileges. If you don't have administrator privileges please go to the next section in order to [run the app as local user](#Run-as-local-user).

1. Download the binary into a folder of your choice
2. Change to the download directory and copy the binary to `/usr/local/bin/`:
     ```
     sudo cp ./agora-app /usr/local/bin/
     ```
3. Give it permissions to execute:
     ```
     sudo chmod +x /usr/local/bin/agora-app
     ```
4. Register the agora-app:
     ```
     sudo agora-app register
     ```
5. Install and run as service:
     ```
     sudo agora-app install --user=$USER --working-directory=$HOME
     sudo agora-app start
     ```

#### Run as local user
1. Download the binary into a folder of your choice and change into it
2. Give it permissions to execute:
     ```
     chmod +x ./agora-app
     ```
3. Register the agora-app:
     ```
     ./agora-app register
     ```
4. Run the app:
     ```
     ./agora-app run
     ```

### macOS
#### Run as service (Recommended)
Running the agora-app as service is the recommended way, but needs root privileges. If you don't have administrator privileges please go to the next section in order to run the app as local user.

1. Download the binary into a folder of your choice and and change into it
2. Give it permissions to execute:
     ```
     sudo chmod +x ./agora-app
     ```
3. Register the agora-app:
     ```
     sudo agora-app register
     ```
4. Install and run as service:
     ```
     sudo agora-app install
     sudo agora-app start
     ```

***Limitations on macOS***: *The service needs to be installed from a Terminal window logged in as your current user. Only then will you be able to manage the service.*


#### Run as local user
1. Download the binary into a folder of your choice and change into it
2. Give it permissions to execute:
     ```
     chmod +x ./agora-app
     ```
3. Register the agora-app:
     ```
     ./agora-app register
     ```
4. Run the app:
     ```
     ./agora-app run
     ```

### Self-Signed Certificates
the app might not be able to connect if your Agora server uses a self-signed certificate. In that case you can disable the certificate check while registering the app:
     ```
     ./agora-app register --no-certificate-check
     ```



## Upload
The agora-app can also be used to upload a file or folder from the command linee with the following syntax:

```
     agora-app upload --path <file_or_folder> <options>
```

```
OPTIONS:
   -p, --path           The path to a file or folder to be uploaded
   -f, --target-folder  The ID of the target folder where the data is uploaded to (default: -1)
   --extract-zip        If the uploaded file is a zip, it is extracted and its content is imported into Agora (default: false)
   -j, --import-json    The json which will be used for the import
   --fake               Run the uploader without actually uploading the files (for testing and debugging) (default: false)
   -h, --help           show help (default: false)
```

### Examples

1. Upload a file into the Agora folder with ID = 13
     ```
          agora-app upload --path /data/my_dicom.dcm --target-folder 13
     ```

2. Upload an entire folder
     ```
          agora-app upload -p /data/ -f 13
     ```

3. Upload a .zip file and import its content
     ```
          agora-app upload -p /data/my_data.zip -f 13  --extract-zip 
     ```
