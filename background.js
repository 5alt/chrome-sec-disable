//https://www.owasp.org/index.php/OWASP_Secure_Headers_Project

var isSecDisabled = false;

var onHeadersReceived = function(details) {
  if (!isSecDisabled) {
      for (var i = 0; i < details.responseHeaders.length; i++) {
        if ('content-security-policy' === details.responseHeaders[i].name.toLowerCase()) {
          details.responseHeaders[i].value = details.responseHeaders[i].value.replace('report-uri', 'nope').replace('report-to', 'nope');
        }else if ('content-security-policy-report-only' === details.responseHeaders[i].name.toLowerCase()) {
          details.responseHeaders[i].value = details.responseHeaders[i].value.replace('report-uri', 'nope').replace('report-to', 'nope');
        }
      }
  }else{
      for (var i = 0; i < details.responseHeaders.length; i++) {
        if ('content-security-policy' === details.responseHeaders[i].name.toLowerCase()) {
          details.responseHeaders[i].value = '';
        }else if ('content-security-policy-report-only' === details.responseHeaders[i].name.toLowerCase()) {
          details.responseHeaders[i].value = '';
        }else if ('x-frame-options' === details.responseHeaders[i].name.toLowerCase()) {
          details.responseHeaders[i].value = 'allow-from: *';
        }else if ('x-xss-protection' === details.responseHeaders[i].name.toLowerCase()) {
          details.responseHeaders[i].value = '0';
        }else if ('x-content-type-options' === details.responseHeaders[i].name.toLowerCase()) {
          details.responseHeaders[i].value = 'sniff';
        }else if ('x-permitted-cross-domain-policies' === details.responseHeaders[i].name.toLowerCase()) {
          details.responseHeaders[i].value = 'all';
        }
      }
  }

  return {
    responseHeaders: details.responseHeaders
  };
};

var updateUI = function() {
  var iconName = isSecDisabled ? 'on' : 'off';
  var title    = isSecDisabled ? 'disabled' : 'enabled';

  chrome.browserAction.setIcon({ path: "images/icon38-" + iconName + ".png" });
  chrome.browserAction.setTitle({ title: 'Content-Security-Policy headers are ' + title });
};

var filter = {
  urls: ["*://*/*"],
  types: ["main_frame", "sub_frame"]
};

chrome.webRequest.onHeadersReceived.addListener(onHeadersReceived, filter, ["blocking", "responseHeaders"]);

chrome.browserAction.onClicked.addListener(function() {
  isSecDisabled = !isSecDisabled;

  if (isSecDisabled) {
    chrome.browsingData.remove({}, {"serviceWorkers": true}, function () {});
  }

  updateUI()
});

updateUI();
