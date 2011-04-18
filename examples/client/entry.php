<?php
require_once "common.php";
if(!empty($_POST['submit'])){
	echo("Location: ".__OAUTH2_TEST_ENDPOINT_AUTHORIZE__."?response_type=".$_POST['response_type']."&client_id=".__OAUTH2_TEST_CLIENT_ID__."&redirect_uri=".__OAUTH2_TEST_REDIRECT_URI__);
	header("Location: ".__OAUTH2_TEST_ENDPOINT_AUTHORIZE__."?response_type=".$_POST['response_type']."&client_id=".__OAUTH2_TEST_CLIENT_ID__."&redirect_uri=".__OAUTH2_TEST_REDIRECT_URI__);

	exit();
}

?>
<HTML>
<BODY>
<?php
echo "CLIENT_ID: ".__OAUTH2_TEST_CLIENT_ID__."<BR>";
echo "CLIENT_SECRET: ".__OAUTH2_TEST_CLIENT_SECRET__."<BR>";
echo "USER_ID: ".__OAUTH2_TEST_USER_ID__."<BR>";
echo "USER_SECRET: ".__OAUTH2_TEST_USER_SECRET__."<BR>";
?>
<FORM METHOD=POST>
request_method:
	<INPUT NAME="request_method" VALUE="GET" TYPE="RADIO" CHECKED> GET, &nbsp;&nbsp;
	<INPUT NAME="request_method" VALUE="POST" TYPE="RADIO"> POST <BR>
response_type:
	<INPUT NAME="response_type" VALUE="code" TYPE="RADIO" CHECKED> code, &nbsp;&nbsp;
	<INPUT NAME="response_type" VALUE="token" TYPE="RADIO"> token <BR>
	<INPUT NAME="submit" VALUE="submit" TYPE="SUBMIT"><BR>
</FORM>

</BODY>
</HTML>
