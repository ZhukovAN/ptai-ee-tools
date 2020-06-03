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
            onEmptyPtaiUrlError: function(elem) {
                $("ptaiUrlError").innerHTML = elem.firstChild.nodeValue;
                that.highlightErrorField($("ptaiUrl"));
            },
            onInvalidPtaiUrlError: function(elem) {
                $("ptaiUrlError").innerHTML = elem.firstChild.nodeValue;
                that.highlightErrorField($("ptaiUrl"));
            },
            onEmptyPtaiUserError: function(elem) {
                $("ptaiUserError").innerHTML = elem.firstChild.nodeValue;
                that.highlightErrorField($("ptaiUser"));
            },
            onEmptyPtaiTokenError: function(elem) {
                $("ptaiTokenError").innerHTML = elem.firstChild.nodeValue;
                that.highlightErrorField($("ptaiToken"));
            },
            onEmptyPtaiTrustedCertificatesError: function(elem) {
                $("ptaiTrustedCertificatesError").innerHTML = elem.firstChild.nodeValue;
                that.highlightErrorField($("ptaiTrustedCertificates"));
            },
            onInvalidPtaiTrustedCertificatesError: function(elem) {
                $("ptaiTrustedCertificatesError").innerHTML = elem.firstChild.nodeValue;
                that.highlightErrorField($("ptaiTrustedCertificates"));
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
