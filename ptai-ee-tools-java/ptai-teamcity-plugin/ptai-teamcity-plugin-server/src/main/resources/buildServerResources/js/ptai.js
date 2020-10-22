/*
* Need to create form that can be bound to any element (native BS forms
* use form.elements property that doesn't works with something else than
* forms, i.e. div's). So I've overriden methods like enable / disable and
* ported disableFormTemp / reenableForm from BS.Util.
* In order to use this form on page, extend it and override formElement
* and savingIndicator methods. Form on that page also need to provide
* hidden "mode" field. This field may have following values:
* - modify - something was changed on a form, no buttons were pressed.
* Just to mark form as modified
* - save - user clicked "save" button, so settings are to be checked and
* saved to file
* - test - user clicked "test" button, settings are to be checked and
* connectivity test is to be performed*
* */
PtaiConnectionSettingsForm = OO.extend(BS.AbstractPasswordForm, {
    mode: 'modify',
    /*
    * As we have two points where connection verification takes place,
    * we need to create single function that will process error messages
    * regarding incorrect field values
    * */
    createErrorListener: function() {
        let that = this;
        return OO.extend(BS.ErrorsAwareListener, {
            handle: function(field, elem) {
                $("error_" + field).innerHTML = elem.firstChild.nodeValue;
                that.highlightErrorField($(field));
            },

            onPtaiUrlError: function(elem) {
                this.handle("ptaiUrl", elem);
            },

            onPtaiTokenError: function(elem) {
                this.handle("ptaiToken", elem);
            },

            onPtaiCertificatesError: function(elem) {
                this.handle("ptaiCertificates", elem);
            },

            onCompleteSave: function(form, xml, err) {
                // Call parent listener onCompleteSave method to reenable
                // controls, stop spinning saving progress, show error fields etc.
                BS.ErrorsAwareListener.onCompleteSave(form, xml, err);
                // If we have errors in the fields, all of them are processed above, so just exit
                if (err) return;
                form.enable();
                // If there weren't message from the server about connection settings
                // result - that's strange, let's inform user about that
                if (!xml) {
                    BS.TestConnectionDialog.show(false, "Empty server response");
                    return;
                }
                // If we are saving no matter if connection test succeeded or not
                if ("save" === form.mode) {
                    BS.XMLResponse.processRedirect(xml);
                    return;
                }
                let status = xml.getElementsByTagName("testConnectionResult")[0].textContent;
                let success = status && status.includes("SUCCESS");

                let details = xml.getElementsByTagName("testConnectionDetails")[0];
                let detailsString = "No additional info available";
                if (details) {
                    let lines = details.getElementsByTagName("line");
                    detailsString = "";
                    for (let i = 0; i < lines.length; i++) {
                        if (0 !== i) detailsString += "\n";
                        detailsString += lines[i].textContent;
                    }
                }
                BS.TestConnectionDialog.show(success, detailsString);
            }
        });
    },

    formElement: function() {
        return $('connection-settings');
    },

    /*
    * Need to override this as form may have more than one saving indicator
    * */
    savingIndicator: function() {
        return $('saving');
    },

    /*
    * This class used to disable parts of a real form so its
    * formElement isn't necessary an HTML form so we can't use parent functions
    * as those are use forms.element property that is undefined if formElement
    * points to a <div> tag
    * */
    disable: function(elementsFilter) {
        if (this._formDisabled) return;
        // Parent disable method calls BS.Util.disableFormTemp that isn't suitable if
        // formElement isn't a form, so we need to do custom implementation
        // TODO: Check if formElement is a form and call parent method
        let disabledElems = this.disableFormTemp(this.formElement(), elementsFilter);
        this._formDisabled = true;
        return disabledElems;
    },

    /*
    * See comments to disable method
    * */
    enable: function(elementsFilter) {
        // Parent disable method calls BS.Util.reenableForm that isn't suitable if
        // formElement isn't a form, so we need to do custom implementation
        // TODO: Check if formElement is a form and call parent method
        if (this._formDisabled)
            this.reenableForm(this.formElement(), elementsFilter);
        let modifiedMessageForm = this._modifiedMessageForm();
        if (modifiedMessageForm)
            this.reenableForm(modifiedMessageForm);
        this._formDisabled = false;
    },

    /*
    * Custom implementation that allows disabling child controls
    * even if formElement isn't a form
    * */
    disableFormTemp: function(form, elemsFilter) {
        let disabledElems = [];
        let inputs = form.querySelectorAll("input, select, textarea");
        for (let i = 0; i < inputs.length; i++) {
            let element = inputs[i];
            if (!elemsFilter || elemsFilter(element)) {
                BS.Util.disableInputTemp(element);
                disabledElems.push(element);
            }
        }
        BS.VisibilityHandlers.updateVisibility(form);
        return disabledElems;
    },

    /*
    * Custom implementation that allows enabling child controls
    * even if formElement isn't a form
    * */
    reenableForm: function(form, elemsFilter) {
        let inputs = form.querySelectorAll("input, select, textarea");
        for (let i = 0; i < inputs.length; i++) {
            let element = inputs[i];
            if (!elemsFilter || elemsFilter(element)) {
                BS.Util.reenableInput(element);
            }
        }
        BS.VisibilityHandlers.updateVisibility(form);
    },

    setupEventHandlers(form) {
        form.setUpdateStateHandlers({
            updateState: function() {
                form.modify();
            },
            saveState: function() {
                form.save();
            }
        });
    },

    modify: function() {
        this.mode = 'modify';
        BS.PasswordFormSaver.save(this, this.formElement().action, BS.StoreInSessionListener);
    },

    save: function() {
        this.mode = 'save';
        BS.PasswordFormSaver.save(this, this.action(), this.createErrorListener());
        return false;
    },

    test: function() {
        this.mode = 'test';
        BS.PasswordFormSaver.save(this, this.action(), this.createErrorListener());
    },

    /*
    * As formElement may be not a form, we might need to override URL in
    * descendant classes that aren't form-bound
     */
    action: function() {
        return this.formElement().action;
    },

    /*
    * Need to override AbstractPasswordForm's serializeParameters as that method
    * uses getEncryptedPassword call that isn't implemented for "props:passwordProperty"
     */
    serializeParameters: function(addMode = true) {
        let params = BS.AbstractWebForm.serializeParameters.bind(this)();
        if (addMode) params += "&mode=" + this.mode;
        let passwordFields = Form.getInputs(this.formElement(), "password");
        if (!passwordFields) return params;
        for (let i = 0; i < passwordFields.length; i++) {
            if (BS.Util.isParameterIgnored(passwordFields[i])) continue;
            let name = passwordFields[i].name;
            // Skip Chrome autofill workaround fields
            if (0 === name.length) continue;

            let encryptedField = name.replace("prop:", "prop:encrypted:");

            params += "&" + encryptedField + "=";

            if (0 === passwordFields[i].value.length) continue;
            // The "prop:encrypted:${name}" hidden field is initialized with encrypted
            // password value and cleaned on any change of password field
            let encryptedValue = "";
            if (0 === $(encryptedField).value.length)
                encryptedValue = BS.Encrypt.encryptData(passwordFields[i].value, this.publicKey());
            else
                encryptedValue = $(encryptedField).value;
            params += encryptedValue;
        }
        return params;
    }
});

GlobalConnectionSettingsForm = OO.extend(PtaiConnectionSettingsForm, {
    formElement: function() {
        return $('adminForm');
    },

    savingIndicator: function() {
        return $('saving');
    },

    setupEventHandlers() {
        $('test').on('click', this.test.bindAsEventListener(this));
        PtaiConnectionSettingsForm.setupEventHandlers(this);
    }
});

TaskConnectionSettingsForm = OO.extend(PtaiConnectionSettingsForm, {
    formElement: function() {
        return $('ptai-connection-settings');
    },

    savingIndicator: function() {
        return $('testingConnection');
    },

    /*
    * No need to setupEventHandlers as there's form saver already exist
    * and listens for events
    * */
    setupEventHandlers() {
        $('testConnection').on('click', this.test.bindAsEventListener(this));
    },

    setTestUrl(url) {
        this.testUrl = url;
    },

    action: function() {
        return this.testUrl;
    },

    /*
    * For build step settings publicKey field is generated by TeamCity and
    * isn't a part of connection settings area, so we need to add it manually
    * */
    serializeParameters: function(addMode = true) {
        let params = PtaiConnectionSettingsForm.serializeParameters.bind(this, addMode)();
        params += "&publicKey=";
        params += $("publicKey").value;
        return params;
    },

    toggle: function(global) {
        if (global)
            $j("#ptai-connection-settings").find(".ptai-connection-settings-local").hide();
        else
            $j("#ptai-connection-settings").find(".ptai-connection-settings-local").show();
        BS.MultilineProperties.updateVisible();
        BS.VisibilityHandlers.updateVisibility('mainContent');
    }
});

TaskScanSettingsForm = OO.extend(PtaiConnectionSettingsForm, {
    formElement: function () {
        return $('ptai-scan-settings');
    },

    savingIndicator: function () {
        return $('testingSettings');
    },

    /*
    * No need to setupEventHandlers as there's form saver already exist
    * and listens for events
    * */
    setupEventHandlers() {
        $('testSettings').on('click', this.test.bindAsEventListener(this));
    },

    setTestUrl(url) {
        this.testUrl = url;
    },

    action: function () {
        return this.testUrl;
    },

    /*
    * For build step settings publicKey field is generated by TeamCity and
    * isn't a part of connection settings area, so we need to add it manually
    * */
    serializeParameters: function () {
        let params = PtaiConnectionSettingsForm.serializeParameters.bind(this)();
        params += "&" + TaskConnectionSettingsForm.serializeParameters(false);
        return params;
    },

    test: function () {
        this.mode = 'check';
        BS.PasswordFormSaver.save(this, this.action(), this.createErrorListener());
    },

    toggle: function (ui) {
        if (ui) {
            $j("#ptai-scan-settings").find(".ptai-scan-settings-ui").show();
            $j("#ptai-scan-settings").find(".ptai-scan-settings-json").hide();
        } else {
            $j("#ptai-scan-settings").find(".ptai-scan-settings-ui").hide();
            $j("#ptai-scan-settings").find(".ptai-scan-settings-json").show();
        }
        BS.MultilineProperties.updateVisible();
        BS.VisibilityHandlers.updateVisibility('mainContent');
    },

    createErrorListener: function () {
        let that = this;
        let parentListener = PtaiConnectionSettingsForm.createErrorListener();
        return OO.extend(parentListener, {
            onPtaiProjectNameError: function (elem) {
                parentListener.handle("ptaiProjectName", elem);
            },

            onPtaiJsonSettingsError: function (elem) {
                parentListener.handle("ptaiJsonSettings", elem);
            },

            onPtaiJsonPolicyError: function (elem) {
                parentListener.handle("ptaiJsonPolicy", elem);
            }
        });
    }
});