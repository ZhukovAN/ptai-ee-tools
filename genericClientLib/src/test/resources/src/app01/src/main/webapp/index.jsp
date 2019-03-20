<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Small vulnerable web application</title>
<link rel="stylesheet" href="/app01/js/Bootstrap/css/bootstrap.min.css" />
<link rel="stylesheet" href="/app01/js/Bootstrap/css/callouts.css" />
</head>
<body>
<div class="container">
    <form>
        <legend>Employee search</legend>
        <div class="form-group">
            <label for="NAME">First name:</label>
            <input type="text" id = "NAME" name="NAME" placeholder="Enter first name" class="form-control">
        </div>
        <button type="button" id="RUN" class="btn">Find</button>
    </form>
    <div id="RESULT"></div>
    <script type="text/javascript" src="/app01/js/jQuery/jquery-2.0.1.js"></script>
    <script type="text/javascript" src="/app01/js/Moment/moment-with-locales.js"></script>
    <script type="text/javascript" src="/app01/js/Bootstrap/js/bootstrap.min.js"></script>
    <script type="text/javascript" src="/app01/js/exploit.js"></script>
    <script>
	    $(function() {
	    	$("#RUN").click( function() {
	    		var l_strName = $('#NAME').val();
	    	    $.get("/app01/servlet", { NAME : l_strName }, function(responseText) {
	    	        $('#RESULT').html(responseText);
	    	    });
	    	});
	    });
    </script>
</div>
</body>
</html>