$(function() {
  resize();
  window.onresize = resize;

  function getTab() {
  	var respDisplay = document.getElementById("response").style.display;
  	return (respDisplay == "" || respDisplay == "none") ? "#request" : "#response";
  }

  function resize() {
  	var tab = getTab();
  	if ($("body").width() < 768) {
  		var rowHeight = $(tab).find(".row").height();
  		var headerHeight = $(tab).find(".headers").height() + 25;
  	  var bodyContHeight = rowHeight - headerHeight;
  	  if (rowHeight - headerHeight > 250) {
  		$(tab).find(".bodyContainer").css("height", rowHeight - headerHeight);
  	  } else {
  	  	$(tab).find(".bodyContainer").css("height", 250);
  	  }
  	  $(".headerVal").css("width", "calc(100% - 139px)");
  	  $(".lastHeader").css("width", "calc(100% - 172px)");
  	} else {
  	  $(".headerVal").css("width", "calc(100% - 125px)");
  	  $(".lastHeader").css("width", "calc(100% - 158px)");
  	  $(tab).find(".bodyContainer").css("height", "100%");
  	}
  }

  function displayHeaders(headers) {
    var myNode = document.getElementById("respHeaders");
	while (myNode.firstChild) {
      myNode.removeChild(myNode.firstChild);
	}
	var i;
    for (i = 0; i < headers.length - 1; i++) {
      var header = headers[i].split(": ");
      $("#respHeaders").append('<input type="text" class="popupInput headerName newHeader" value="' + header[0] + '" readonly>');
      $("#respHeaders").append('<input type="text" class="popupInput headerVal" value="' + header[1] + '" readonly>');
    }
  }

  $('.dropdown-menu li a').click(function() {
    $(this).parents('.btn-group').find('.dropdown-toggle').html($(this).text() + '<span class="caret"></span>');
  });

  $('#reqTabButt').click(function() {
  	$('#response').css("display", "none");
  	$('#request').css("display", "block");
  	$('#respTabButt').css("border-bottom", "1px solid #ccc");
  	$('#reqTabButt').css("border-bottom", "none");
  	$('#reqTabButt').css("border-top", "1px solid #ccc");
  	$('#respTabButt').css("border-right", "none");
  	$('#respTabButt').css("border-top", "none");
  	$('#reqTabButt').css("border-left", "1px solid #ccc");
  	resize();
  });

  function showResponse() {
  	$('#request').css("display", "none");
  	$('#response').css("display", "block");
  	$('#reqTabButt').css("border-bottom", "1px solid #ccc");
  	$('#reqTabButt').css("border-top", "none");
  	$('#respTabButt').css("border-bottom", "none");
  	$('#respTabButt').css("border-right", "1px solid #ccc");
  	$('#respTabButt').css("border-top", "1px solid #ccc");
  	$('#reqTabButt').css("border-left", "none");
  	resize();
  }

  $('#respTabButt').click(showResponse);

  $('#basicOK').click(function() {
  	$('#basic-auth-value').val(basicAuth($('#username').val(), $('#password').val()));
  	basicAuthDisplay();
  });

  function getHeaderSection() {
    if (document.getElementById("basicInfo").style.display == "block") {
	  // basic auth selected
	  return "basicInfo";
	} else if (document.getElementById("sigInfo").style.display == "block") {
	  // http auth selected
	  return "sigInfo"
	}
  	return "";
  }

  $('.headerAdder').click(function() {
  	var headerSection = getHeaderSection();
  	if (headerSection != "") {
  		// basic or http auth selected
  		$("#" + headerSection).find('.lastHeader').removeClass("lastHeader");
  		$("#" + headerSection).append('<input type="text" class="popupInput headerName newHeader">');
  		$("#" + headerSection).append('<input type="text" class="popupInput headerVal lastHeader">');
  		$("#" + headerSection).find('.headerAdder').insertAfter($("#" + headerSection).find('.lastHeader'));
  		resize();
  	}
  });

  $('#goButton').click(function() {
  	var request = getRequest();
  	request.onerror = function() {}
    request.onload = function() {
      $('#response').find('textarea.form-control').val(request.responseText);
      displayHeaders(request.getAllResponseHeaders().split("\r\n"));
      showResponse();
	}
	request.send($('#request').find('textarea.form-control').val());
  });

  function getRequest() {
  	var request = new XMLHttpRequest();
  	request.open($('#methodSelector').text().substring(0, $('#methodSelector').text().length - 1),
  		         "http://localhost:8080/boh-util-api/service/" + getAuthPath() +  "?URL=" + $('#url').val(),
  		         true);
  	var headerPane = getHeaderPane();
  	if (headerPane != "") {
  		// some auth necessary: parse the headers
  		var headers = document.getElementById(headerPane).childNodes;
  		var i = 1;
  		while (i < headers.length) {
  			if (headers[i].value.trim().length && headers[i+2].value.trim().length) {
  				request.setRequestHeader(headers[i].value, headers[i + 2].value);
  			}
  			i = i + 4;
  		}
  	}
  	return request;
  }

  function getAuthPath() {
  	var authIdentifier = $('#authButton').text().charAt(0);
  	if (authIdentifier == 'A') {
  		return "none";
  	} else if (authIdentifier == 'B') {
  		return "basic";
  	} else {
  		return "signature";
  	}
  }

  // returns id of div with headers w/o '#' in front
  function getHeaderPane() {
	if (document.getElementById('sigInfo').style.display == 'block') {
		return "sigInfo";
	} else if (document.getElementById('basicInfo').style.display == 'block') {
		return "basicInfo";
	} else {
		return "";
	}
  }

  $('#refreshButton').click(produceSigHeaders);

  $('#sigOK').click(produceSigHeaders);

  function produceSigHeaders() {
  	if ($('#url').val().trim().length && $('#key-value').val().trim().length && 
  		$('#keyid-value').val().trim().length && $('#env-value').val().trim().length) {
	  var sigRequest = new XMLHttpRequest();
  	  sigRequest.open($('#methodSelector').text().substring(0, $('#methodSelector').text().length - 1), 
  		              "http://localhost:8080/boh-util-api/service/headers?URL=" + $('#url').val(),
  		              true);
  	  sigRequest.setRequestHeader("keyid", $('#keyid-value').val().trim());
  	  sigRequest.setRequestHeader("key", $('#key-value').val().trim());
  	  sigRequest.setRequestHeader("gws-environment", $('#env-value').val().trim())
  	  sigRequest.onerror = function() {
  	  	sigAuthDisplay();
      }
      sigRequest.onload = function() {
        var headers = sigRequest.responseText.split("\n");
        var i;
        for (i = 0; i < headers.length; i++) {
      	  var index = headers[i].indexOf(" ");
      	  var name = headers[i].substring(0, index)
      	  var value = headers[i].substring(index + 1);
      	  $("#" + name.toLowerCase() + "-name").val(name);
      	  $("#" + name.toLowerCase() + "-val").val(value);
        }
        sigAuthDisplay();
  	  }
  	  sigRequest.send("");
    } else {
  	  sigAuthDisplay();
    }
  }

  function noAuthDisplay() {
	$('#sigInfo').css("display", "none");
	$('#basicInfo').css("display", "none");
	resize();
  }

  function basicAuthDisplay() {
	$('#sigInfo').css("display", "none");
	$('#basicInfo').css("display", "block");
	$('#refreshButton').css("display", "none");
	resize();
  }

  function sigAuthDisplay() {
	$('#sigInfo').css("display", "block");
	$('#basicInfo').css("display", "none");
	$('#refreshButton').css("display", "inline");
	resize();
  }

  function basicAuth(username, password) {
  	return "Basic " + window.btoa(username + ":" + password);
  }
});