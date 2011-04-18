<?php
if(!empty($_GET['code']))echo "Yes, callback page got Authorization Code '$_GET[code]'";
else{
    if($_GET['state']=='test_web_server')
        echo 'Oops, Authorization Code not received!';
    else
        echo 'Callback page could not get Authorization Code.';
}
