<?php
include('./magic.php');

class magical_Game {
    private $magicStarted = true;

    public function magicalbeginGame() {
        if ($this->magicStarted === true) {
            echo "<h1 style='color:white;'><center>Game On! Flag Is: ";
            echo "<br>";
            echo getenv('ctfbd');
            echo "</center></h1>";
        }
    }

    public function magicalendGame() {
        $this->magicStarted = false;
    }
}

if (isset($_GET['magical_game_is_on.php'])) {
    $magic = new magical_Game();
    $magic->magicalbeginGame();
    $magic->magicalendGame();
}
?>