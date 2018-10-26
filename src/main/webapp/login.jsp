<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>

<c:set var="contextPath" value="${pageContext.request.contextPath}"/>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->
    <meta name="description" content="">
    <meta name="author" content="">

    <title>Log in with your account</title>

    <link href="${contextPath}/resources/css/bootstrap.min.css" rel="stylesheet">
    <link href="${contextPath}/resources/css/common.css" rel="stylesheet">
    <link href="${contextPath}/resources/css/main.css" rel="stylesheet">

    <!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
    <!--[if lt IE 9]>
    <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
    <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
</head>

<body id="LoginForm">
<div class="container">
    <h3 class="form-heading">Anti-CSRF Applications Part-1</h3>
    <h5 class="form-heading2">Synchronizer Token Pattern</h5>
    <div class="login-form">
        <div class="main-div">
            <div class="panel">
                <h2>Student Login</h2>
                <p>Please enter your username and password</p>
            </div>
            <form id="Login" action="${contextPath}/login" method="POST" class="form-signin">

                <div class="form-group ${error != null ? 'has-error' : ''}">
                    <span><h4>${message}</h4></span>

                    <input name="username" type="text" class="form-control" placeholder="Username" autofocus="true">

                </div>

                <div class="form-group">

                    <input name="password" type="password" class="form-control" placeholder="Password">
                    <span><h4 style="color: darkred;">${error}</h4></span>
                    <%--This hidden input POST CSRF token data --%>
                    <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
                </div>
                <button class="btn btn-lg btn-primary btn-block" type="submit">Log In</button>
                <h4  class="text-center"><a style="color: white ; font-size: large" href="${contextPath}/registration">Create an account</a></h4>
                <div class="forgot">
                    <a href="reset.html">Forgot password?</a>
                </div>
            </form>
        </div>
        <p class="botto-text">Designed for SSD</p>
        <p class="botto-text">SLIIT &trade;</p>
    </div>
    <%--<div class="container">--%>

    <%--<form method="POST" action="${contextPath}/login" class="form-signin">--%>
    <%--<h2 class="form-heading">Log in</h2>--%>

    <%--<div class="form-group ${error != null ? 'has-error' : ''}">--%>
    <%--<span>${message}</span>--%>
    <%--<input name="username" type="text" class="form-control" placeholder="Username"--%>
    <%--autofocus="true"/>--%>
    <%--<input name="password" type="password" class="form-control" placeholder="Password"/>--%>
    <%--<span>${error}</span>--%>
    <%--<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>--%>

    <%--<button class="btn btn-lg btn-primary btn-block" type="submit">Log In</button>--%>
    <%--<h4 class="text-center"><a href="${contextPath}/registration">Create an account</a></h4>--%>
    <%--</div>--%>

    <%--</form>--%>

    <%--</div>--%>
    <!-- /container -->

       

    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.2/jquery.min.js"></script>
    <script src="${contextPath}/resources/js/bootstrap.min.js"></script>
    <link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
    <script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script>
    <script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
</body>
</html>
