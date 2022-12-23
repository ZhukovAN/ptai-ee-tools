package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Plugin

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import lib.FormTagLib

def f = namespace(FormTagLib)
def st = namespace("jelly:stapler")
def pt = namespace("/com/ptsecurity/appsec/ai/ee/utils/ci/integration/plugin/jenkins/ui")

/*
OOB we can't know which dropdownDescriptorSelector is selected. Moreover, validateButton script that passes data to
plugin doesn't allow direct pass of values, it accepts comma-separated set of HTML elements names, collects these
values and passes that data to server.
So if we fill field values for first dropdownDescriptorSelector descriptor, than select another one and fill
fields for another one, validateButton collects values for both these descriptor and passes it to plugin.
Moreover, there's no reliable way to identify combobox that corresponds to dropdownDescriptorSelector as there's
no distinguished attributes for OOB dropdownDescriptorSelector
So we need to modify dropdownDescriptorSelector and assign unique id. Than we create hidden field and fill its value
with currently selected item and than call validateButton script
 */

// Generate unique element id
scanSettingsId = "ptai-scanSettings-" + UUID.randomUUID()

pt.dropdownDescriptorSelector(
        // OOB dropdownDescriptorSelector lacks ID attribute, need to add it
        id: scanSettingsId,
        title: _('scanSettings'),
        field: 'scanSettings',
        default: descriptor.getDefaultScanSettingsDescriptor(),
        descriptors: descriptor.getScanSettingsDescriptors())

// This invisible element will be filled with currently selected scan settings descriptor
f.invisibleEntry() {
    input(
            type: "hidden",
            // Use unique ID. We must auto generate it because user may add PT AI step twice
            // and there'll be duplicates otherwise
            id: "${scanSettingsId}_value",
            name: "selectedScanSettings",
            value: "")
}

configId = "ptai-config-" + UUID.randomUUID()

pt.dropdownDescriptorSelector(
        id: configId,
        title: _('config'),
        field: 'config',
        default: descriptor.getDefaultConfigDescriptor(),
        descriptors: descriptor.getConfigDescriptors()
)

f.invisibleEntry() {
    input(
            type: "hidden",
            // Use unique ID. We must auto generate it because user may add PT AI step twice
            // and there'll be duplicates otherwise
            id: "${configId}_value",
            name: "selectedConfig",
            value: "")
}

f.block() {
    f.validateButton(
            title: _('testProject'),
            progress: _('testProjectProgress'),
            method: 'testProject',
            with: 'selectedScanSettings,selectedConfig,jsonSettings,jsonPolicy,projectName,serverUrl,serverCredentialsId,serverInsecure,configName',
            customScript: 'testPt(this)'
    )
}

workModeId = "ptai-workMode-" + UUID.randomUUID()

// Had to extend OOB dropdownDescriptorSelector as it lacks ID attribute
// thus making impossible to add event listener that stores currently
// selected item to hidden fields that can be processed by validateButton
pt.dropdownDescriptorSelector(
        id: workModeId,
        title: _('workMode'),
        field: 'workMode',
        default: descriptor.getDefaultWorkModeDescriptor(),
        descriptors: descriptor.getWorkModeDescriptors())

f.invisibleEntry() {
    input(
            type: "hidden",
            // Use unique ID. We must auto generate it because user may add PT AI step twice
            // and there'll be duplicates otherwise
            id: "${workModeId}_value",
            name: "selectedWorkMode",
            value: "")
}

/*
Want to use native validateButton code. Unfortunately it does not allows us to pass parameter values. So we search for
combobox (now it may be done as we've added ID to dropdownDescriptorSelector), read selected item and save value
as hidden element that can be processed by validateButton
 */
script("""
    function triggerEvent(element, event){
        if (document.createEventObject) {
            // dispatch for IE
            var evt = document.createEventObject();
            return element.fireEvent('on'+event,evt);
        } else {
            // dispatch for firefox + others
            var evt = document.createEvent("HTMLEvents");
            evt.initEvent(event, true, true ); // event type,bubbling,cancelable
            return !element.dispatchEvent(evt);
        }
    };

    function storeSelectedValue(e) {
        var cb = e.target;
        // As dropdownDescriptorSelector have no its own readable property to store
        // currently selected item, we need to create corresponding hidden field 
        // and add event handler to read selected item and store it there
        \$(cb.id + "_value").value = cb.options[cb.selectedIndex].text;
        // And as hidden fields do not automatically fire change event, we need to 
        // trigger it explicitly
        triggerEvent(\$(cb.id + "_value"), "change");
    };

    function init() {
        ["${scanSettingsId}", "${configId}", "${workModeId}"].forEach(function (item, index) {
            var cb = document.getElementById(item);
            console.log(item);
            console.log(cb);
            cb.addEventListener("change", storeSelectedValue);
            triggerEvent(cb, "change");
        });
    }
""")

f.entry(
        title: _('transfers')) {
    set('descriptor', descriptor.transferDescriptor)
    f.repeatable(
            var: 'instance',
            items: instance?.transfers,
            name: 'transfers',
            minimum: '1',
            // header: _('transfer'),
            add: _('transferAdd')) {
        table(
                width: '100%',
                padding: '0'
        ) {
            st.include(
                    page: 'config.groovy',
                    class: descriptor?.clazz
            )
            f.entry(
                    title: '') {
                div(align: 'right', class: 'show-if-not-only') {
                    f.repeatableDeleteButton(
                            value: _('transferDelete')
                    )
                }
            }
        }
    }
}

f.advanced() {
    f.entry(
            title: Resources.i18n_ast_settings_advanced_label(),
            field: 'advancedSettings') {
        f.textarea(
                style: 'height:100px',
                checkMethod: 'post')
    }

    f.entry(
            title: _('fullScanMode'),
            field: 'fullScanMode',
            default: 'false') {
        f.checkbox()
    }

    f.entry(
            title: _('verbose'),
            field: 'verbose',
            default: 'false') {
        f.checkbox()
    }
}

script("""
    function waitForElm(selector) {
        return new Promise(function(resolve) {
            if (document.querySelector(selector)) {
                return resolve(document.querySelector(selector));
            }
    
            const observer = new MutationObserver(function(mutations) {
                if (document.querySelector(selector)) {
                    resolve(document.querySelector(selector));
                    observer.disconnect();
                }
            });
    
            observer.observe(document.body, {
                childList: true,
                subtree: true
            });
        });
    }

    waitForElm("div[descriptorid='com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Plugin']").then(function(pluginBody) {
        init();
    });
""")

