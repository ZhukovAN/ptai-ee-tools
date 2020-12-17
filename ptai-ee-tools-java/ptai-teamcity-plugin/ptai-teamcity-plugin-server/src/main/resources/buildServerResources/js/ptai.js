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
PtaiAbstractSettingsForm = OO.extend(BS.AbstractPasswordForm, {
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

            onCompleteSave: function(form, xml, err) {
                let mode = ($('mode') && $('mode').value) ? $('mode').value : '';
                if (0 === mode.length)
                    window.console.error('No mode value found');

                // Call parent listener onCompleteSave method to reenable
                // controls, stop spinning saving progress, show error fields etc.
                BS.ErrorsAwareListener.onCompleteSave(form, xml, err);
                form.enable();

                // If there weren't message from the server about connection settings
                // result - that's strange, let's inform user about that
                if (!xml) {
                    BS.TestConnectionDialog.show(false, "Empty server response");
                    return;
                }
                // If we are saving no matter if connection test succeeded or not
                if ("save" === mode) {
                    BS.XMLResponse.processRedirect(xml);
                    return;
                }
                // As we do not implement "modify" event listener we need to show diagnostic messages even if error fields are already marked red
                // if (err) return;

                // If we are editing then no need to show TestConnectionDialog
                // TODO Investigate if on-the-fly fields verification is required
                // if ("modify" === mode) return;

                let status = xml.getElementsByTagName("testConnectionResult")[0].textContent;
                let success = status && status.includes("SUCCESS");

                let details = xml.getElementsByTagName("testConnectionDetails");
                let detailsString = "No additional info available";
                if (details && details.length > 0) {
                    detailsString = "";
                    for (let i = 0; i < details.length; i++) {
                        if (0 !== i) detailsString += "\n";
                        let lines = details[i].getElementsByTagName("line");
                        for (let j = 0; j < lines.length; j++) {
                            if (0 !== j) detailsString += "\n";
                            detailsString += lines[j].textContent;
                        }
                    }

                }
                BS.TestConnectionDialog.show(success, detailsString);
            }
        });
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
        let safeForm = (form) ? form : this;
        safeForm.setUpdateStateHandlers({
            updateState: function() {
                // TODO Investigate if on-the-fly fields verification is required
                // safeForm.modify();
            },
            saveState: function() {
                safeForm.save();
            }
        });
    },

    modify: function() {
        if ($('mode')) $('mode').value = 'modify';
        BS.PasswordFormSaver.save(this, this.actionUrl(), BS.StoreInSessionListener);
    },

    save: function() {
        if ($('mode')) $('mode').value = 'save';
        BS.PasswordFormSaver.save(this, this.actionUrl(), this.createErrorListener());
        return false;
    },

    test: function() {
        if ($('mode')) $('mode').value = 'test';
        BS.PasswordFormSaver.save(this, this.actionUrl(), this.createErrorListener());
    },

    /*
    * As formElement may be not a form, we might need to override URL in
    * descendant classes that aren't form-bound
     */
    actionUrl: function() {
        return this.formElement().action;
    }
});

PtaiConnectionSettingsForm = OO.extend(PtaiAbstractSettingsForm, {
    createErrorListener: function() {
        let that = this;
        let parentListener = PtaiAbstractSettingsForm.createErrorListener();

        return OO.extend(parentListener, {
            onPtaiServerSettingsError: function(elem) {
                this.handle("ptaiServerSettings", elem);
            },

            onPtaiUrlError: function(elem) {
                this.handle("ptaiUrl", elem);
            },

            onPtaiTokenError: function(elem) {
                this.handle("ptaiToken", elem);
            },

            onPtaiCertificatesError: function(elem) {
                this.handle("ptaiCertificates", elem);
            }
        });
    },

    formElement: function() {
        return $('adminForm');
    },

    setupEventHandlers() {
        $('test').on('click', this.test.bindAsEventListener(this));
        PtaiAbstractSettingsForm.setupEventHandlers(this);
    }
});

PtaiTaskSettingsForm = OO.extend(PtaiAbstractSettingsForm, {

    url: null,

    formElement: function() {
        // return $('ptai-scan-settings');
        return $('editBuildTypeForm');
    },

    createErrorListener: function() {
        let that = this;
        let parentListener = PtaiConnectionSettingsForm.createErrorListener();

        return OO.extend(parentListener, {
            onPtaiProjectNameError: function (elem) {
                this.handle("ptaiProjectName", elem);
            },

            onPtaiJsonSettingsError: function (elem) {
                this.handle("ptaiJsonSettings", elem);
            },

            onPtaiJsonPolicyError: function (elem) {
                this.handle("ptaiJsonPolicy", elem);
            },

            onPtaiIncludesError: function (elem) {
                this.handle("ptaiIncludes", elem);
            },

            onPtaiPatternSeparatorError: function (elem) {
                this.handle("ptaiPatternSeparator", elem);
            }
        });
    },

    /*
    * Need to override this as form may have more than one saving indicator
    * */
    savingIndicator: function() {
        return $('testingSettings');
    },

    actionUrl: function(url) {
        if (url) this.url = url;
        return this.url;
    }
});

