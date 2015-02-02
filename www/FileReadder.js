var fileReader = {
    encryptFile: function(location, successCallback, errorCallback) {
        cordova.exec(
            successCallback, // success callback function
            errorCallback, // error callback function
            'CipherUtil', // mapped to our native Java class called "Calendar"
            'encryptFile', // with this action name
            [{ // and this array of custom arguments to create our entry
                "location": "location"
            }]
        );
    },
    decryptFile: function(location, successCallback, errorCallback) {
        cordova.exec(
            successCallback, // success callback function
            errorCallback, // error callback function
            'Calendar', // mapped to our native Java class called "Calendar"
            'addCalendarEntry', // with this action name
            [{ // and this array of custom arguments to create our entry
                "title": title,
                "description": notes,
                "eventLocation": location,
                "startTimeMillis": startDate.getTime(),
                "endTimeMillis": endDate.getTime()
            }]
        );
    }
};

module.exports = fileReader;
