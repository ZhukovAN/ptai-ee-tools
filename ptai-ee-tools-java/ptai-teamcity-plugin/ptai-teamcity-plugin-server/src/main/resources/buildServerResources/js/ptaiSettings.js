var PtaiAdmin = {}

PtaiAdmin.SettingsForm = OO.extend(BS.AbstractPasswordForm, {
    setupEventHandlers: function() {
        var that = this;
        $('testConnection').on('click', this.testConnection.bindAsEventListener(this));

        this.setUpdateStateHandlers({
            updateState: function() {
                that.storeInSession();
            },
            saveState: function() {
                that.submitSettings();
            }
        });
    },

    storeInSession: function() {
        $("submitSettings").value = 'storeInSession';
        BS.PasswordFormSaver.save(this, this.formElement().action, BS.StoreInSessionListener);
    },

    submitSettings: function() {
        $("submitSettings").value = 'store';
        // this.removeUpdateStateHandlers();
        BS.PasswordFormSaver.save(this, this.formElement().action,
            OO.extend(BS.ErrorsAwareListener, this.createErrorListener()));
        return false;
    },

    createErrorListener: function() {
        var that = this;
        return {
            onPtaiServerUrlError: function(elem) {
                $("ptaiServerUrlError").innerHTML = elem.firstChild.nodeValue;
            },
            onCaCertsPemError: function(elem) {
                $("caCertsPemError").innerHTML = elem.firstChild.nodeValue;
            },
            onPtaiKeyPemError: function(elem) {
                $("ptaiKeyPemError").innerHTML = elem.firstChild.nodeValue;
            },
            onJenkinsServerUrlError: function(elem) {
                $("jenkinsServerUrlError").innerHTML = elem.firstChild.nodeValue;
            },
            onJenkinsJobNameError: function(elem) {
                $("jenkinsJobNameError").innerHTML = elem.firstChild.nodeValue;
            },
            onJenkinsLoginError: function(elem) {
                $("jenkinsLoginError").innerHTML = elem.firstChild.nodeValue;
            },
            onCompleteSave: function(form, responseXML, err) {
                BS.ErrorsAwareListener.onCompleteSave(form, responseXML, err);
                if (!err) {
                    BS.XMLResponse.processRedirect(responseXML);
                } else {
                    // that.setupEventHandlers();
                }
            }
        }
    },

    testConnection: function () {
        $("submitSettings").value = 'testConnection';
        var listener = OO.extend(BS.ErrorsAwareListener, this.createErrorListener());
        var oldOnCompleteSave = listener['onCompleteSave'];
        listener.onCompleteSave = function (form, responseXML, err) {
            oldOnCompleteSave(form, responseXML, err);
            if (!err) {
                form.enable();
                if (responseXML) {
                    var res = responseXML.getElementsByTagName("testConnectionResult")[0].
                        firstChild.nodeValue;
                    var success = res.includes("Test completed successfully")
                    BS.TestConnectionDialog.show(success, res, $('testConnection'));
                }
            }
        };
        BS.PasswordFormSaver.save(this, this.formElement().action, listener);
    }
});
