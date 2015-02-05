var mediaFileReader = {
    encryptFile: function(location, successCallback, errorCallback) {
        cordova.exec(
            successCallback, // success callback function
            errorCallback, // error callback function
            'CipherUtil', // mapped to our native Java class called "Calendar"
            'encryptFile', // with this action name
            [{ // and this array of custom arguments to create our entry
                "location": location
            }]
        );
    },

    decryptFile: function(location, successCallback, errorCallback) {
        cordova.exec(
            successCallback, // success callback function
            errorCallback, // error callback function
            'CipherUtil', // mapped to our native Java class called "Calendar"
            'decryptFile', // with this action name
            [{ // and this array of custom arguments to create our entry
                "location": location
            }]
        );
    }
};

module.exports = mediaFileReader;
