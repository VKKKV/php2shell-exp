<?php
$warm = str_repeat('W', 12 * 1024 * 1024);
unset($warm);
echo "warmed pid=", getmypid(), "\n";
