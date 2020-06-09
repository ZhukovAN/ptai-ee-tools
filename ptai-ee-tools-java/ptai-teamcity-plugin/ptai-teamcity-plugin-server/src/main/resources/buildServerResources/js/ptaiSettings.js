var PtaiAdmin = {}

PtaiAdmin.SettingsForm = OO.extend(BS.AbstractPasswordForm, {
    setupEventHandlers: function() {
        var that = this;
        $('test').on('click', this.test.bindAsEventListener(this));

        this.setUpdateStateHandlers({
            updateState: function() {
                that.storeToSession();
            },
            saveState: function() {
                that.storeToFile();
            }
        });
    },

    storeToSession: function() {
        $("submitMode").value = 'storeToSession';
        BS.PasswordFormSaver.save(this, this.formElement().action, BS.StoreInSessionListener);
    },

    storeToFile: function() {
        $("submitMode").value = 'storeToFile';
        // this.removeUpdateStateHandlers();
        BS.PasswordFormSaver.save(
            this, this.formElement().action,
            OO.extend(BS.ErrorsAwareListener, this.createErrorListener()));
        return false;
    },

    createErrorListener: function() {
        var that = this;
        return {
            onEmptyPtaiGlobalUrlError: function(elem) {
                $("ptaiGlobalUrlError").innerHTML = elem.firstChild.nodeValue;
                that.highlightErrorField($("ptaiGlobalUrl"));
            },
            onInvalidPtaiGlobalUrlError: function(elem) {
                $("ptaiGlobalUrlError").innerHTML = elem.firstChild.nodeValue;
                that.highlightErrorField($("ptaiGlobalUrl"));
            },
            onEmptyPtaiGlobalUserError: function(elem) {
                $("ptaiGlobalUserError").innerHTML = elem.firstChild.nodeValue;
                that.highlightErrorField($("ptaiGlobalUser"));
            },
            onEmptyPtaiGlobalTokenError: function(elem) {
                $("ptaiGlobalTokenError").innerHTML = elem.firstChild.nodeValue;
                that.highlightErrorField($("ptaiGlobalToken"));
            },
            onEmptyPtaiGlobalTrustedCertificatesError: function(elem) {
                $("ptaiGlobalTrustedCertificatesError").innerHTML = elem.firstChild.nodeValue;
                that.highlightErrorField($("ptaiGlobalTrustedCertificates"));
            },
            onInvalidPtaiGlobalTrustedCertificatesError: function(elem) {
                $("ptaiGlobalTrustedCertificatesError").innerHTML = elem.firstChild.nodeValue;
                that.highlightErrorField($("ptaiGlobalTrustedCertificates"));
            },
            onCompleteSave: function(form, xml, err) {
                BS.ErrorsAwareListener.onCompleteSave(form, xml, err);
                if (err)
                    ;
                    // that.setupEventHandlers();
                else
                    BS.XMLResponse.processRedirect(xml);
            }
        }
    },

    test: function () {
        $("submitMode").value = 'test';
        var listener = OO.extend(BS.ErrorsAwareListener, this.createErrorListener());
        var oldOnCompleteSave = listener['onCompleteSave'];
        listener.onCompleteSave = function (form, xml, err) {
            oldOnCompleteSave(form, xml, err);
            if (err) return;
            form.enable();
            if (!xml) return;

            var res = xml.getElementsByTagName("testConnectionResult")[0].textContent;
            var success = res.includes("SUCCESS")

            res = xml.getElementsByTagName("testConnectionDetails")[0];
            var details = res.getElementsByTagName("line");
            var detailsString = "";
            for (let i = 0; i < details.length; i++) {
                if (0 != i) detailsString += "\n"
                detailsString += details[i].textContent;
            }
            BS.TestConnectionDialog.show(success, detailsString, $('test'));
        };
        BS.PasswordFormSaver.save(this, this.formElement().action, listener);
    }
});
