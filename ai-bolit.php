<?php
///////////////////////////////////////////////////////////////////////////
// Created and developed by Greg Zemskov, Revisium Company
// Email: audit@revisium.com, http://revisium.com/ai/

// Commercial usage is not allowed without a license purchase or written permission of the author
// Source code and signatures usage is not allowed

// Certificated in Federal Institute of Industrial Property in 2012
// http://revisium.com/ai/i/mini_aibolit.jpg

////////////////////////////////////////////////////////////////////////////
// Запрещено использование скрипта в коммерческих целях без приобретения лицензии.
// Запрещено использование исходного кода скрипта и сигнатур.
//
// По вопросам приобретения лицензии обращайтесь в компанию "Ревизиум": http://www.revisium.com
// audit@revisium.com
// На скрипт получено авторское свидетельство в Роспатенте
// http://revisium.com/ai/i/mini_aibolit.jpg
///////////////////////////////////////////////////////////////////////////
ini_set('memory_limit', '1G');
ini_set('xdebug.max_nesting_level', 500);

$int_enc = @ini_get('mbstring.internal_encoding');
        
define('SHORT_PHP_TAG', strtolower(ini_get('short_open_tag')) == 'on' || strtolower(ini_get('short_open_tag')) == 1 ? true : false);

// Put any strong password to open the script from web
// Впишите вместо put_any_strong_password_here сложный пароль	 

define('PASS', '????????????????'); 

//////////////////////////////////////////////////////////////////////////

if (isCli()) {
	if (strpos('--eng', $argv[$argc - 1]) !== false) {
		  define('LANG', 'EN');  
	}
} else {
   define('NEED_REPORT', true);
}
	
if (!defined('LANG')) {
   define('LANG', 'RU');  
}	

// put 1 for expert mode, 0 for basic check and 2 for paranoic mode
// установите 1 для режима "Эксперта", 0 для быстрой проверки и 2 для параноидальной проверки (для лечения сайта) 
define('AI_EXPERT_MODE', 1); 

define('REPORT_MASK_PHPSIGN', 1);
define('REPORT_MASK_SPAMLINKS', 2);
define('REPORT_MASK_DOORWAYS', 4);
define('REPORT_MASK_SUSP', 8);
define('REPORT_MASK_CANDI', 16);
define('REPORT_MASK_WRIT', 32);
define('REPORT_MASK_FULL', REPORT_MASK_PHPSIGN | REPORT_MASK_DOORWAYS | REPORT_MASK_SUSP
/* <-- remove this line to enable "recommendations"  

| REPORT_MASK_SPAMLINKS 

 remove this line to enable "recommendations" --> */
);

define('AI_HOSTER', 0); 

define('AI_EXTRA_WARN', 0);

$defaults = array(
	'path' => dirname(__FILE__),
	'scan_all_files' => (AI_EXPERT_MODE == 2), // full scan (rather than just a .js, .php, .html, .htaccess)
	'scan_delay' => 0, // delay in file scanning to reduce system load
	'max_size_to_scan' => '600K',
	'site_url' => '', // website url
	'no_rw_dir' => 0,
    	'skip_ext' => '',
        'skip_cache' => false,
	'report_mask' => REPORT_MASK_FULL
);

define('DEBUG_MODE', 0);
define('DEBUG_PERFORMANCE', 0);

define('AIBOLIT_START_TIME', time());
define('START_TIME', microtime(true));

define('DIR_SEPARATOR', '/');

define('AIBOLIT_MAX_NUMBER', 200);

define('DOUBLECHECK_FILE', 'AI-BOLIT-DOUBLECHECK.php');

if ((isset($_SERVER['OS']) && stripos('Win', $_SERVER['OS']) !== false)/* && stripos('CygWin', $_SERVER['OS']) === false)*/) {
   define('DIR_SEPARATOR', '\\');
}

$g_SuspiciousFiles = array('cgi', 'pl', 'o', 'so', 'py', 'sh', 'phtml', 'php3', 'php4', 'php5', 'php6', 'php7', 'pht', 'shtml');
$g_SensitiveFiles = array_merge(array('php', 'js', 'htaccess', 'html', 'htm', 'tpl', 'inc', 'css', 'txt', 'sql', 'ico', '', 'susp', 'suspected', 'zip', 'tar'), $g_SuspiciousFiles);
$g_CriticalFiles = array('php', 'htaccess', 'cgi', 'pl', 'o', 'so', 'py', 'sh', 'phtml', 'php3', 'php4', 'php5', 'php6', 'php7', 'pht', 'shtml', 'susp', 'suspected', 'infected', 'vir', 'ico', '');
$g_CriticalEntries = '^\s*<\?php|^\s*<\?=|^#!/usr|^#!/bin|\beval|assert|base64_decode|\bsystem|create_function|\bexec|\bpopen|\bfwrite|\bfputs|file_get_|call_user_func|file_put_|\$_REQUEST|ob_start|\$_GET|\$_POST|\$_SERVER|\$_FILES|\bmove|\bcopy|\barray_|reg_replace|\bmysql_|\bchr|fsockopen|\$GLOBALS|sqliteCreateFunction';
$g_VirusFiles = array('js', 'html', 'htm', 'suspicious');
$g_VirusEntries = '<\s*script|<\s*iframe|<\s*object|<\s*embed|fromCharCode|setTimeout|setInterval|location\.|document\.|window\.|navigator\.|\$(this)\.';
$g_PhishFiles = array('js', 'html', 'htm', 'suspected', 'php', 'pht', 'php7');
$g_PhishEntries = '<\s*title|<\s*html|<\s*form|<\s*body|bank|account';
$g_ShortListExt = array('php', 'php3', 'php4', 'php5', 'php6', 'php7', 'pht', 'html', 'htm', 'phtml', 'shtml', 'khtml', '', 'ico', 'txt');

if (LANG == 'RU') {
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// RUSSIAN INTERFACE
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
$msg1 = "\"Отображать по _MENU_ записей\"";
$msg2 = "\"Ничего не найдено\"";
$msg3 = "\"Отображается c _START_ по _END_ из _TOTAL_ файлов\"";
$msg4 = "\"Нет файлов\"";
$msg5 = "\"(всего записей _MAX_)\"";
$msg6 = "\"Поиск:\"";
$msg7 = "\"Первая\"";
$msg8 = "\"Предыдущая\"";
$msg9 = "\"Следующая\"";
$msg10 = "\"Последняя\"";
$msg11 = "\": активировать для сортировки столбца по возрастанию\"";
$msg12 = "\": активировать для сортировки столбцов по убыванию\"";

define('AI_STR_001', 'Отчет сканера <a href="https://revisium.com/ai/">AI-Bolit</a> v@@VERSION@@:');
define('AI_STR_002', 'Обращаем внимание на то, что большинство CMS <b>без дополнительной защиты</b> рано или поздно <b>взламывают</b>.<p> Компания <a href="https://revisium.com/">"Ревизиум"</a> предлагает услугу превентивной защиты сайта от взлома с использованием уникальной <b>процедуры "цементирования сайта"</b>. Подробно на <a href="https://revisium.com/ru/client_protect/">странице услуги</a>. <p>Лучшее лечение &mdash; это профилактика.');
define('AI_STR_003', 'Не оставляйте файл отчета на сервере, и не давайте на него прямых ссылок с других сайтов. Информация из отчета может быть использована злоумышленниками для взлома сайта, так как содержит информацию о настройках сервера, файлах и каталогах.');
define('AI_STR_004', 'Путь');
define('AI_STR_005', 'Изменение свойств');
define('AI_STR_006', 'Изменение содержимого');
define('AI_STR_007', 'Размер');
define('AI_STR_008', 'Конфигурация PHP');
define('AI_STR_009', "Вы установили слабый пароль на скрипт AI-BOLIT. Укажите пароль не менее 8 символов, содержащий латинские буквы в верхнем и нижнем регистре, а также цифры. Например, такой <b>%s</b>");
define('AI_STR_010', "Сканер AI-Bolit запускается с паролем. Если это первый запуск сканера, вам нужно придумать сложный пароль и вписать его в файле ai-bolit.php в строке №34. <p>Например, <b>define('PASS', '%s');</b><p>
После этого откройте сканер в браузере, указав пароль в параметре \"p\". <p>Например, так <b>http://mysite.ru/ai-bolit.php?p=%s</b>. ");
define('AI_STR_011', 'Текущая директория не доступна для чтения скрипту. Пожалуйста, укажите права на доступ <b>rwxr-xr-x</b> или с помощью командной строки <b>chmod +r имя_директории</b>');
define('AI_STR_012', "Затрачено времени: <b>%s</b>. Сканирование начато %s, сканирование завершено %s");
define('AI_STR_013', 'Всего проверено %s директорий и %s файлов.');
define('AI_STR_014', '<div class="rep" style="color: #0000A0">Внимание, скрипт выполнил быструю проверку сайта. Проверяются только наиболее критические файлы, но часть вредоносных скриптов может быть не обнаружена. Пожалуйста, запустите скрипт из командной строки для выполнения полного тестирования. Подробнее смотрите в <a href="https://revisium.com/ai/faq.php">FAQ вопрос №10</a>.</div>');
define('AI_STR_015', '<div class="title">Критические замечания</div>');
define('AI_STR_016', 'Эти файлы могут быть вредоносными или хакерскими скриптами');
define('AI_STR_017', 'Вирусы и вредоносные скрипты не обнаружены.');
define('AI_STR_018', 'Эти файлы могут быть javascript вирусами');
define('AI_STR_019', 'Обнаружены сигнатуры исполняемых файлов unix и нехарактерных скриптов. Они могут быть вредоносными файлами');
define('AI_STR_020', 'Двойное расширение, зашифрованный контент или подозрение на вредоносный скрипт. Требуется дополнительный анализ');
define('AI_STR_021', 'Подозрение на вредоносный скрипт');
define('AI_STR_022', 'Символические ссылки (symlinks)');
define('AI_STR_023', 'Скрытые файлы');
define('AI_STR_024', 'Возможно, каталог с дорвеем');
define('AI_STR_025', 'Не найдено директорий c дорвеями');
define('AI_STR_026', 'Предупреждения');
define('AI_STR_027', 'Подозрение на мобильный редирект, подмену расширений или автовнедрение кода');
define('AI_STR_028', 'В не .php файле содержится стартовая сигнатура PHP кода. Возможно, там вредоносный код');
define('AI_STR_029', 'Дорвеи, реклама, спам-ссылки, редиректы');
define('AI_STR_030', 'Непроверенные файлы - ошибка чтения');
define('AI_STR_031', 'Невидимые ссылки. Подозрение на ссылочный спам');
define('AI_STR_032', 'Невидимые ссылки');
define('AI_STR_033', 'Отображены только первые ');
define('AI_STR_034', 'Подозрение на дорвей');
define('AI_STR_035', 'Скрипт использует код, который часто встречается во вредоносных скриптах');
define('AI_STR_036', 'Директории из файла .adirignore были пропущены при сканировании');
define('AI_STR_037', 'Версии найденных CMS');
define('AI_STR_038', 'Большие файлы (больше чем %s). Пропущено');
define('AI_STR_039', 'Не найдено файлов больше чем %s');
define('AI_STR_040', 'Временные файлы или файлы(каталоги) - кандидаты на удаление по ряду причин');
define('AI_STR_041', 'Потенциально небезопасно! Директории, доступные скрипту на запись');
define('AI_STR_042', 'Не найдено директорий, доступных на запись скриптом');
define('AI_STR_043', 'Использовано памяти при сканировании: ');
define('AI_STR_044', 'Просканированы только файлы, перечисленные в ' . DOUBLECHECK_FILE . '. Для полного сканирования удалите файл ' . DOUBLECHECK_FILE . ' и запустите сканер повторно.');
define('AI_STR_045', '<div class="rep">Внимание! Выполнена экспресс-проверка сайта. Просканированы только файлы с расширением .php, .js, .html, .htaccess. В этом режиме могут быть пропущены вирусы и хакерские скрипты в файлах с другими расширениями. Чтобы выполнить более тщательное сканирование, поменяйте значение настройки на <b>\'scan_all_files\' => 1</b> в строке 50 или откройте сканер в браузере с параметром full: <b><a href="ai-bolit.php?p=' . PASS . '&full">ai-bolit.php?p=' . PASS . '&full</a></b>. <p>Не забудьте перед повторным запуском удалить файл ' . DOUBLECHECK_FILE . '</div>');
define('AI_STR_050', 'Замечания и предложения по работе скрипта и не обнаруженные вредоносные скрипты присылайте на <a href="mailto:ai@revisium.com">ai@revisium.com</a>.<p>Также будем чрезвычайно благодарны за любые упоминания скрипта AI-Bolit на вашем сайте, в блоге, среди друзей, знакомых и клиентов. Ссылочку можно поставить на <a href="https://revisium.com/ai/">https://revisium.com/ai/</a>. <p>Если будут вопросы - пишите <a href="mailto:ai@revisium.com">ai@revisium.com</a>. ');
define('AI_STR_051', 'Отчет по ');
define('AI_STR_052', 'Эвристический анализ обнаружил подозрительные файлы. Проверьте их на наличие вредоносного кода.');
define('AI_STR_053', 'Много косвенных вызовов функции');
define('AI_STR_054', 'Подозрение на обфусцированные переменные');
define('AI_STR_055', 'Подозрительное использование массива глобальных переменных');
define('AI_STR_056', 'Дробление строки на символы');
define('AI_STR_057', 'Сканирование выполнено в экспресс-режиме. Многие вредоносные скрипты могут быть не обнаружены.<br> Рекомендуем проверить сайт в режиме "Эксперт" или "Параноидальный". Подробно описано в <a href="https://revisium.com/ai/faq.php">FAQ</a> и инструкции к скрипту.');
define('AI_STR_058', 'Обнаружены фишинговые страницы');

define('AI_STR_059', 'Мобильных редиректов');
define('AI_STR_060', 'Вредоносных скриптов');
define('AI_STR_061', 'JS Вирусов');
define('AI_STR_062', 'Фишинговых страниц');
define('AI_STR_063', 'Исполняемых файлов');
define('AI_STR_064', 'IFRAME вставок');
define('AI_STR_065', 'Пропущенных больших файлов');
define('AI_STR_066', 'Ошибок чтения файлов');
define('AI_STR_067', 'Зашифрованных файлов');
define('AI_STR_068', 'Подозрительных (эвристика)');
define('AI_STR_069', 'Символических ссылок');
define('AI_STR_070', 'Скрытых файлов');
define('AI_STR_072', 'Рекламных ссылок и кодов');
define('AI_STR_073', 'Пустых ссылок');
define('AI_STR_074', 'Сводный отчет');
define('AI_STR_075', 'Сканер бесплатный только для личного некоммерческого использования. Информация по <a href="https://revisium.com/ai/faq.php#faq11" target=_blank>коммерческой лицензии</a> (пункт №11). <a href="https://revisium.com/images/mini_aibolit.jpg">Авторское свидетельство</a> о гос. регистрации в РосПатенте №2012619254 от 12 октября 2012 г.');

$tmp_str = <<<HTML_FOOTER
   <div class="disclaimer"><span class="vir">[!]</span> Отказ от гарантий: невозможно гарантировать обнаружение всех вредоносных скриптов. Поэтому разработчик сканера не несет ответственности за возможные последствия работы сканера AI-Bolit или неоправданные ожидания пользователей относительно функциональности и возможностей.
   </div>
   <div class="thanx">
      Замечания и предложения по работе скрипта, а также не обнаруженные вредоносные скрипты вы можете присылать на <a href="mailto:ai@revisium.com">ai@revisium.com</a>.<br/>
      Также будем чрезвычайно благодарны за любые упоминания сканера AI-Bolit на вашем сайте, в блоге, среди друзей, знакомых и клиентов. <br/>Ссылку можно поставить на страницу <a href="https://revisium.com/ai/">https://revisium.com/ai/</a>.<br/> 
     <p>Получить консультацию или задать вопросы можно по email <a href="mailto:ai@revisium.com">ai@revisium.com</a>.</p> 
	</div>
HTML_FOOTER;

define('AI_STR_076', $tmp_str);
define('AI_STR_077', "Подозрительные параметры времени изменения файла");
define('AI_STR_078', "Подозрительные атрибуты файла");
define('AI_STR_079', "Подозрительное местоположение файла");
define('AI_STR_080', "Обращаем внимание, что обнаруженные файлы не всегда являются вирусами и хакерскими скриптами. Сканер минимизирует число ложных обнаружений, но это не всегда возможно, так как найденный фрагмент может встречаться как во вредоносных скриптах, так и в обычных.<p>Для диагностического сканирования без ложных срабатываний мы разработали специальную версию <u><a href=\"https://revisium.com/ru/blog/ai-bolit-4-ISP.html\" target=_blank style=\"background: none; color: #303030\">сканера для хостинг-компаний</a></u>.");
define('AI_STR_081', "Уязвимости в скриптах");
define('AI_STR_082', "Добавленные файлы");
define('AI_STR_083', "Измененные файлы");
define('AI_STR_084', "Удаленные файлы");
define('AI_STR_085', "Добавленные каталоги");
define('AI_STR_086', "Удаленные каталоги");
define('AI_STR_087', "Изменения в файловой структуре");

$l_Offer =<<<OFFER
    <div>
	 <div class="crit" style="font-size: 17px; margin-bottom: 20px"><b>Внимание! Наш сканер обнаружил подозрительный или вредоносный код</b>.</div> 
	 <p>Возможно, ваш сайт был взломан. Рекомендуем срочно <a href="https://revisium.com/ru/order/#fform" target=_blank>проконсультироваться со специалистами</a> по данному отчету.</p>
	 <p><hr size=1></p>
	 <p>Рекомендуем также проверить сайт бесплатным <b><a href="https://rescan.pro/?utm=aibolit" target=_blank>онлайн-сканером ReScan.Pro</a></b>.</p>
	 <p><hr size=1></p>
         <div class="caution">@@CAUTION@@</div>
    </div>
OFFER;

$l_Offer2 =<<<OFFER2
	   <b>Наши продукты:</b><br/>
              <ul>
               <li style="margin-top: 10px"><font color=red><sup>[new]</sup></font><b><a href="https://revisium.com/ru/products/antivirus_for_ispmanager/" target=_blank>Антивирус для ISPmanager Lite</a></b> &mdash;  сканирование и лечение сайтов прямо в панели хостинга</li>
               <li style="margin-top: 10px"><b><a href="https://revisium.com/ru/blog/revisium-antivirus-for-plesk.html" target=_blank>Антивирус для Plesk</a> Onyx 17.x</b> &mdash;  сканирование и лечение сайтов прямо в панели хостинга</li>
               <li style="margin-top: 10px"><b><a href="https://cloudscan.pro/ru/" target=_blank>Облачный антивирус CloudScan.Pro</a> для веб-специалистов</b> &mdash; лечение сайтов в один клик</li>
               <li style="margin-top: 10px"><b><a href="https://revisium.com/ru/antivirus-server/" target=_blank>Антивирус для сервера</a></b> &mdash; для хостин-компаний, веб-студий и агентств.</li>
              </ul>  
	</div>
OFFER2;

} else {
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ENGLISH INTERFACE
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
$msg1 = "\"Display _MENU_ records\"";
$msg2 = "\"Not found\"";
$msg3 = "\"Display from _START_ to _END_ of _TOTAL_ files\"";
$msg4 = "\"No files\"";
$msg5 = "\"(total _MAX_)\"";
$msg6 = "\"Filter/Search:\"";
$msg7 = "\"First\"";
$msg8 = "\"Previous\"";
$msg9 = "\"Next\"";
$msg10 = "\"Last\"";
$msg11 = "\": activate to sort row ascending order\"";
$msg12 = "\": activate to sort row descending order\"";

define('AI_STR_001', 'AI-Bolit v@@VERSION@@ Scan Report:');
define('AI_STR_002', '');
define('AI_STR_003', 'Caution! Do not leave either ai-bolit.php or report file on server and do not provide direct links to the report file. Report file contains sensitive information about your website which could be used by hackers. So keep it in safe place and don\'t leave on website!');
define('AI_STR_004', 'Path');
define('AI_STR_005', 'iNode Changed');
define('AI_STR_006', 'Modified');
define('AI_STR_007', 'Size');
define('AI_STR_008', 'PHP Info');
define('AI_STR_009', "Your password for AI-BOLIT is too weak. Password must be more than 8 character length, contain both latin letters in upper and lower case, and digits. E.g. <b>%s</b>");
define('AI_STR_010', "Open AI-BOLIT with password specified in the beggining of file in PASS variable. <br/>E.g. http://you_website.com/ai-bolit.php?p=<b>%s</b>");
define('AI_STR_011', 'Current folder is not readable. Please change permission for <b>rwxr-xr-x</b> or using command line <b>chmod +r folder_name</b>');
define('AI_STR_012', "<div class=\"rep\">%s malicious signatures known, %s virus signatures and other malicious code. Elapsed: <b>%s</b
>.<br/>Started: %s. Stopped: %s</div> ");
define('AI_STR_013', 'Scanned %s folders and %s files.');
define('AI_STR_014', '<div class="rep" style="color: #0000A0">Attention! Script has performed quick scan. It scans only .html/.js/.php files  in quick scan mode so some of malicious scripts might not be detected. <br>Please launch script from a command line thru SSH to perform full scan.');
define('AI_STR_015', '<div class="title">Critical</div>');
define('AI_STR_016', 'Shell script signatures detected. Might be a malicious or hacker\'s scripts');
define('AI_STR_017', 'Shell scripts signatures not detected.');
define('AI_STR_018', 'Javascript virus signatures detected:');
define('AI_STR_019', 'Unix executables signatures and odd scripts detected. They might be a malicious binaries or rootkits:');
define('AI_STR_020', 'Suspicious encoded strings, extra .php extention or external includes detected in PHP files. Might be a malicious or hacker\'s script:');
define('AI_STR_021', 'Might be a malicious or hacker\'s script:');
define('AI_STR_022', 'Symlinks:');
define('AI_STR_023', 'Hidden files:');
define('AI_STR_024', 'Files might be a part of doorway:');
define('AI_STR_025', 'Doorway folders not detected');
define('AI_STR_026', 'Warnings');
define('AI_STR_027', 'Malicious code in .htaccess (redirect to external server, extention handler replacement or malicious code auto-append):');
define('AI_STR_028', 'Non-PHP file has PHP signature. Check for malicious code:');
define('AI_STR_029', 'This script has black-SEO links or linkfarm. Check if it was installed by yourself:');
define('AI_STR_030', 'Reading error. Skipped.');
define('AI_STR_031', 'These files have invisible links, might be black-seo stuff:');
define('AI_STR_032', 'List of invisible links:');
define('AI_STR_033', 'Displayed first ');
define('AI_STR_034', 'Folders contained too many .php or .html files. Might be a doorway:');
define('AI_STR_035', 'Suspicious code detected. It\'s usually used in malicious scrips:');
define('AI_STR_036', 'The following list of files specified in .adirignore has been skipped:');
define('AI_STR_037', 'CMS found:');
define('AI_STR_038', 'Large files (greater than %s! Skipped:');
define('AI_STR_039', 'Files greater than %s not found');
define('AI_STR_040', 'Files recommended to be remove due to security reason:');
define('AI_STR_041', 'Potentially unsafe! Folders which are writable for scripts:');
define('AI_STR_042', 'Writable folders not found');
define('AI_STR_043', 'Memory used: ');
define('AI_STR_044', 'Quick scan through the files from ' . DOUBLECHECK_FILE . '. For full scan remove ' . DOUBLECHECK_FILE . ' and launch scanner once again.');
define('AI_STR_045', '<div class="notice"><span class="vir">[!]</span> Ai-BOLIT is working in quick scan mode, only .php, .html, .htaccess files will be checked. Change the following setting \'scan_all_files\' => 1 to perform full scanning.</b>. </div>');
define('AI_STR_050', "I'm sincerely appreciate reports for any bugs you may found in the script. Please email me: <a href=\"mailto:audit@revisium.com\">audit@revisium.com</a>.<p> Also I appriciate any reference to the script in your blog or forum posts. Thank you for the link to download page: <a href=\"https://revisium.com/aibo/\">https://revisium.com/aibo/</a>");
define('AI_STR_051', 'Report for ');
define('AI_STR_052', 'Heuristic Analyzer has detected suspicious files. Check if they are malware.');
define('AI_STR_053', 'Function called by reference');
define('AI_STR_054', 'Suspected for obfuscated variables');
define('AI_STR_055', 'Suspected for $GLOBAL array usage');
define('AI_STR_056', 'Abnormal split of string');
define('AI_STR_057', 'Scanning has been done in simple mode. It is strongly recommended to perform scanning in "Expert" mode. See readme.txt for details.');
define('AI_STR_058', 'Phishing pages detected:');

define('AI_STR_059', 'Mobile redirects');
define('AI_STR_060', 'Malware');
define('AI_STR_061', 'JS viruses');
define('AI_STR_062', 'Phishing pages');
define('AI_STR_063', 'Unix executables');
define('AI_STR_064', 'IFRAME injections');
define('AI_STR_065', 'Skipped big files');
define('AI_STR_066', 'Reading errors');
define('AI_STR_067', 'Encrypted files');
define('AI_STR_068', 'Suspicious (heuristics)');
define('AI_STR_069', 'Symbolic links');
define('AI_STR_070', 'Hidden files');
define('AI_STR_072', 'Adware and spam links');
define('AI_STR_073', 'Empty links');
define('AI_STR_074', 'Summary');
define('AI_STR_075', 'For non-commercial use only. In order to purchase the commercial license of the scanner contact us at ai@revisium.com');

$tmp_str =<<<HTML_FOOTER
		   <div class="disclaimer"><span class="vir">[!]</span> Disclaimer: We're not liable to you for any damages, including general, special, incidental or consequential damages arising out of the use or inability to use the script (including but not limited to loss of data or report being rendered inaccurate or failure of the script). There's no warranty for the program. Use at your own risk. 
		   </div>
		   <div class="thanx">
		      We're greatly appreciate for any references in the social medias, forums or blogs to our scanner AI-BOLIT <a href="https://revisium.com/aibo/">https://revisium.com/aibo/</a>.<br/> 
		     <p>Contact us via email if you have any questions regarding the scanner or need report analysis: <a href="mailto:ai@revisium.com">ai@revisium.com</a>.</p> 
			</div>
HTML_FOOTER;
define('AI_STR_076', $tmp_str);
define('AI_STR_077', "Suspicious file mtime and ctime");
define('AI_STR_078', "Suspicious file permissions");
define('AI_STR_079', "Suspicious file location");
define('AI_STR_081', "Vulnerable Scripts");
define('AI_STR_082', "Added files");
define('AI_STR_083', "Modified files");
define('AI_STR_084', "Deleted files");
define('AI_STR_085', "Added directories");
define('AI_STR_086', "Deleted directories");
define('AI_STR_087', "Integrity Check Report");

$l_Offer =<<<HTML_OFFER_EN
<div>
 <div class="crit" style="font-size: 17px;"><b>Attention! The scanner has detected suspicious or malicious files.</b></div> 
 <br/>Most likely the website has been compromised. Please, <a href="https://revisium.com/en/contacts/" target=_blank>contact web security experts</a> from Revisium to check the report or clean the malware.
 <p><hr size=1></p>
 Also check your website for viruses with our free <b><a href="http://rescan.pro/?en&utm=aibo" target=_blank>online scanner ReScan.Pro</a></b>.
</div>
<br/>
<div>
   Revisium contacts: <a href="mailto:ai@revisium.com">ai@revisium.com</a>, <a href="https://revisium.com/en/contacts/">https://revisium.com/en/home/</a>
</div>
<div class="caution">@@CAUTION@@</div>
HTML_OFFER_EN;

$l_Offer2 = '<b>Special Offers:</b><br/>
              <ul>
               <li style="margin-top: 10px"><font color=red><sup>[new]</sup></font><b><a href="http://ext.plesk.com/packages/b71916cf-614e-4b11-9644-a5fe82060aaf-revisium-antivirus">Antivirus for Plesk Onyx</a></b> hosting panel with one-click malware cleanup and scheduled website scanning.</li>
               <li style="margin-top: 10px"><font color=red></font><b><a href="https://www.ispsystem.com/addons-modules/revisium">Antivirus for ISPmanager Lite</a></b> hosting panel with one-click malware cleanup and scheduled website scanning.</li>
               <li style="margin-top: 10px">Professional malware cleanup and web-protection service with 6 month guarantee for only $99 (one-time payment): <a href="https://revisium.com/en/home/#order_form">https://revisium.com/en/home/</a>.</li>
              </ul>  
	</div>';

define('AI_STR_080', "Notice! Some of detected files may not contain malicious code. Scanner tries to minimize a number of false positives, but sometimes it's impossible, because same piece of code may be used either in malware or in normal scripts.");
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

$l_Template =<<<MAIN_PAGE
<html>
<head>
<!-- revisium.com/ai/ -->
<meta http-equiv="Content-Type" content="text/html;charset=utf-8" >
<META NAME="ROBOTS" CONTENT="NOINDEX,NOFOLLOW">
<title>@@HEAD_TITLE@@</title>
<style type="text/css" title="currentStyle">
	@import "https://cdn.revisium.com/ai/media/css/demo_page2.css";
	@import "https://cdn.revisium.com/ai/media/css/jquery.dataTables2.css";
</style>

<script type="text/javascript" language="javascript" src="https://cdn.revisium.com/ai/jquery.js"></script>
<script type="text/javascript" language="javascript" src="https://cdn.revisium.com/ai/datatables.min.js"></script>

<style type="text/css">
 body 
 {
   font-family: Tahoma;
   color: #5a5a5a;
   background: #FFFFFF;
   font-size: 14px;
   margin: 20px;
   padding: 0;
 }

.header
 {
   font-size: 34px;
   margin: 0 0 10px 0;
 }

 .hidd
 {
    display: none;
 }
 
 .ok
 {
    color: green;
 }
 
 .line_no
 {
   -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   background: #DAF2C1;
   padding: 2px 5px 2px 5px;
   margin: 0 5px 0 5px;
 }
 
 .credits_header 
 {
  -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   background: #F2F2F2;
   padding: 10px;
   font-size: 11px;
    margin: 0 0 10px 0;
 }
 
 .marker
 {
    color: #FF0090;
	font-weight: 100;
	background: #FF0090;
	padding: 2px 0px 2px 0px;
	width: 2px;
 }
 
 .title
 {
   font-size: 24px;
   margin: 20px 0 10px 0;
   color: #9CA9D1;
}

.summary 
{
  float: left;
  width: 500px;
}

.summary TD
{
  font-size: 12px;
  border-bottom: 1px solid #F0F0F0;
  font-weight: 700;
  padding: 10px 0 10px 0;
}
 
.crit, .vir
{
  color: #D84B55;
}

.intitem
{
  color:#4a6975;
}

.spacer
{
   margin: 0 0 50px 0;
   clear:both;
}

.warn
{
  color: #F6B700;
}

.clear
{
   clear: both;
}

.offer
{
  -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   width: 500px;
   background: #F2F2F2;
   color: #747474;
   font-family: Helvetica, Arial;
   padding: 30px;
   margin: 20px 0 0 550px;
   font-size: 14px;
}

.offer2
{
  -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   width: 500px;
   background: #f6f5e0;
   color: #747474;
   font-family: Helvetica, Arial;
   padding: 30px;
   margin: 20px 0 0 550px;
   font-size: 14px;
}


HR {
  margin-top: 15px;
  margin-bottom: 15px;
  opacity: .2;
}
 
.flist
{
   font-family: Henvetica, Arial;
}

.flist TD
{
   font-size: 11px;
   padding: 5px;
}

.flist TH
{
   font-size: 12px;
   height: 30px;
   padding: 5px;
   background: #CEE9EF;
}


.it
{
   font-size: 14px;
   font-weight: 100;
   margin-top: 10px;
}

.crit .it A {
   color: #E50931; 
   line-height: 25px;
   text-decoration: none;
}

.warn .it A {
   color: #F2C900; 
   line-height: 25px;
   text-decoration: none;
}



.details
{
   font-family: Calibri;
   font-size: 12px;
   margin: 10px 10px 10px 0px;
}

.crit .details
{
   color: #A08080;
}

.warn .details
{
   color: #808080;
}

.details A
{
  color: #FFF;
  font-weight: 700;
  text-decoration: none;
  padding: 2px;
  background: #E5CEDE;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;
}

.details A:hover
{
   background: #A0909B;
}

.ctd
{
   margin: 10px 0px 10px 0;
   align:center;
}

.ctd A 
{
   color: #0D9922;
}

.disclaimer
{
   color: darkgreen;
   margin: 10px 10px 10px 0;
}

.note_vir
{
   margin: 10px 0 10px 0;
   //padding: 10px;
   color: #FF4F4F;
   font-size: 15px;
   font-weight: 700;
   clear:both;
  
}

.note_warn
{
   margin: 10px 0 10px 0;
   color: #F6B700;
   font-size: 15px;
   font-weight: 700;
   clear:both;
}

.note_int
{
   margin: 10px 0 10px 0;
   color: #60b5d6;
   font-size: 15px;
   font-weight: 700;
   clear:both;
}

.updateinfo
{
  color: #FFF;
  text-decoration: none;
  background: #E5CEDE;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;

  margin: 10px 0 10px 0px;   
  padding: 10px;
}


.caution
{
  color: #EF7B75;
  text-decoration: none;
  margin: 20px 0 0px 0px;   
  font-size: 12px;
}

.footer
{
  color: #303030;
  text-decoration: none;
  background: #F4F4F4;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;

  margin: 80px 0 10px 0px;   
  padding: 10px;
}

.rep
{
  color: #303030;
  text-decoration: none;
  background: #94DDDB;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;

  margin: 10px 0 10px 0px;   
  padding: 10px;
  font-size: 12px;
}

</style>

</head>
<body>

<div class="header">@@MAIN_TITLE@@ @@PATH_URL@@ (@@MODE@@)</div>
<div class="credits_header">@@CREDITS@@</div>
<div class="details_header">
   @@STAT@@<br/>
   @@SCANNED@@ @@MEMORY@@.
 </div>

 @@WARN_QUICK@@
 
 <div class="summary">
@@SUMMARY@@
 </div>
 
 <div class="offer">
@@OFFER@@
 </div>

 <div class="offer2">
@@OFFER2@@
 </div> 
 
 <div class="clear"></div>
 
 @@MAIN_CONTENT@@
 
	<div class="footer">
	@@FOOTER@@
	</div>
	
<script language="javascript">

function hsig(id) {
  var divs = document.getElementsByTagName("tr");
  for(var i = 0; i < divs.length; i++){
     
     if (divs[i].getAttribute('o') == id) {
        divs[i].innerHTML = '';
     }
  }

  return false;
}


$(document).ready(function(){
    $('#table_crit').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
		"paging": true,
       "iDisplayLength": 500,
		"oLanguage": {
			"sLengthMenu": $msg1,
			"sZeroRecords": $msg2,
			"sInfo": $msg3,
			"sInfoEmpty": $msg4,
			"sInfoFiltered": $msg5,
			"sSearch":       $msg6,
			"sUrl":          "",
			"oPaginate": {
				"sFirst": $msg7,
				"sPrevious": $msg8,
				"sNext": $msg9,
				"sLast": $msg10
			},
			"oAria": {
				"sSortAscending": $msg11,
				"sSortDescending": $msg12	
			}
		}

     } );

});

$(document).ready(function(){
    $('#table_vir').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
		"paging": true,
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
       "iDisplayLength": 500,
		"oLanguage": {
			"sLengthMenu": $msg1,
			"sZeroRecords": $msg2,
			"sInfo": $msg3,
			"sInfoEmpty": $msg4,
			"sInfoFiltered": $msg5,
			"sSearch":       $msg6,
			"sUrl":          "",
			"oPaginate": {
				"sFirst": $msg7,
				"sPrevious": $msg8,
				"sNext": $msg9,
				"sLast": $msg10
			},
			"oAria": {
				"sSortAscending":  $msg11,
				"sSortDescending": $msg12	
			}
		},

     } );

});

if ($('#table_warn0')) {
    $('#table_warn0').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
		"paging": true,
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
			         "iDisplayLength": 500,
			  		"oLanguage": {
			  			"sLengthMenu": $msg1,
			  			"sZeroRecords": $msg2,
			  			"sInfo": $msg3,
			  			"sInfoEmpty": $msg4,
			  			"sInfoFiltered": $msg5,
			  			"sSearch":       $msg6,
			  			"sUrl":          "",
			  			"oPaginate": {
			  				"sFirst": $msg7,
			  				"sPrevious": $msg8,
			  				"sNext": $msg9,
			  				"sLast": $msg10
			  			},
			  			"oAria": {
			  				"sSortAscending":  $msg11,
			  				"sSortDescending": $msg12	
			  			}
		}

     } );
}

if ($('#table_warn1')) {
    $('#table_warn1').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
		"paging": true,
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
			         "iDisplayLength": 500,
			  		"oLanguage": {
			  			"sLengthMenu": $msg1,
			  			"sZeroRecords": $msg2,
			  			"sInfo": $msg3,
			  			"sInfoEmpty": $msg4,
			  			"sInfoFiltered": $msg5,
			  			"sSearch":       $msg6,
			  			"sUrl":          "",
			  			"oPaginate": {
			  				"sFirst": $msg7,
			  				"sPrevious": $msg8,
			  				"sNext": $msg9,
			  				"sLast": $msg10
			  			},
			  			"oAria": {
			  				"sSortAscending":  $msg11,
			  				"sSortDescending": $msg12	
			  			}
		}

     } );
}


</script>
<!-- @@SERVICE_INFO@@  -->
 </body>
</html>
MAIN_PAGE;

$g_AiBolitAbsolutePath = dirname(__FILE__);

if (file_exists($g_AiBolitAbsolutePath . '/ai-design.html')) {
  $l_Template = file_get_contents($g_AiBolitAbsolutePath . '/ai-design.html');
}

$l_Template = str_replace('@@MAIN_TITLE@@', AI_STR_001, $l_Template);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//BEGIN_SIG 19/06/2018 11:21:23
$g_DBShe = unserialize(gzinflate(/*1529396483*/base64_decode("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")));
$gX_DBShe = unserialize(gzinflate(/*1529396483*/base64_decode("bVX9b+I4EP1XvDn2oFIpCUmgpNvqKLDtXT9V2L1dVVVkEhOsOB9rO7Swuvvbzx67tFodv5A8j59n3htPcDTwop80ck9ENIyclKxwQrhzQiNPIf0gcr5XDUpwiepGIoyKNERCclpmOqavYo4jp17XYk0Y05CvoEE/cj6ldIMShoU4dZasSnK0lNuaeM7Z+5VUVvUvyFIWzplmCgx5MhrtyUMD8XC4hwYm8dvFFKfpViNDu4+u90HHJujzC5BpZKQQT6X5N1miuQ5DS9jsaSE8TyuxoWw3f2XwQI4wci5xkpNURaMxW+ElkdVXymWDTZQV5NaX+7M93zLOZcWL4RtjYPHrKmnEOzy0qb1WeaTkhQVd6ihycCnpG/vQshRbwMgLSQA/NpmY2u5ywKBoZakO6ji8QF2OuiswEsrWmRPUpJhVAu1wxpsdlbCsqw/VKa2CCIEzgk4R4SSLOamZapiO8zGcfOz3nUPkmL/XwIMT2K918VTuteociZx5jQuSts8+LTlY3dcaBW7kCCKTqsop6SBd0Q8WP5NljNOClnEjCC/VPgdZUi2gr2wlTBC66qyaMpG0KmPyQoUUHQcEiUGRgwPYoaUNVRp0hTpUxAlmDC+ZSt8EIVym6IM6CnOOtxY9bKVU6CjNb3m0E35geDqtmvBCoN+R+zJxXfcAnZ7uH39COHikqkspR727C9T7BrC2yB8oljJhTUo6rXg+e/g6e3hsXy4W9/EX9RaPL2a3i/aTOXZk2njJ3WfhwyX1tW+Bqqi9lrJOj5KqXLUP25t1pRR4fUtWme4h/aQAal5gt2fr6NW8SnpiK3q50piw3hYXuFdLrryNRVLVBMK1i31fCb7BrLOijMQZkbEilaTUgusY3zaSkveZU2nk7W0w78FyYFuwdXF9dz6+nj+2Y/WDJTAnhJ17Y9ragvavxhhUNdk7ZwRwaGOUormrpIB74Gvt+wrKCkxZVxSy7tLyiB1lVZUxoiQqIMxOCNVt3HWh5/2RvVlTPQng2oPkgR2V07dRGXg29BHdr5WUL1v0BLgdB49JlRK+M5gWyNcD8kO3+5suBCVFeuq0wPPxZDK7Xzio2zUjMLCz4OmRV02ZdtyDJ5A5CF+HCi3GUr4lpwXwlIhTzPMJJ8+fOSVlCuIEQ5N43mfM91OAbNlX+ZXn+0OARpbhcjy5mk3R+Xc0X9w93MD4da17N+qKqW+CEQXIQ89uu+FH87Xq6DUuv3mjAaz1zeCaEppijv+F7g99eyn+omWtRlpV7AAOTKxXDv1Eem4JYGjPvVLfnXnOm1pd7MqcO/h/mqGhmZAyo7tLbGiODcj9jV9mQWkIRgY8v1b1frn9E5IbuHbUckmTnJE/nJN//gM=")));
$g_FlexDBShe = unserialize(gzinflate(/*1529396483*/base64_decode("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")));
$gX_FlexDBShe = unserialize(gzinflate(/*1529396483*/base64_decode("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")));
$gXX_FlexDBShe = unserialize(gzinflate(/*1529396483*/base64_decode("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")));
$g_ExceptFlex = unserialize(gzinflate(/*1529396483*/base64_decode("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")));
$g_AdwareSig = unserialize(gzinflate(/*1529396483*/base64_decode("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")));
$g_PhishingSig = unserialize(gzinflate(/*1529396483*/base64_decode("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")));
$g_JSVirSig = unserialize(gzinflate(/*1529396483*/base64_decode("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")));
$gX_JSVirSig = unserialize(gzinflate(/*1529396483*/base64_decode("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")));
$g_SusDB = unserialize(gzinflate(/*1529396483*/base64_decode("jVgLc9u4Ef4t1bhpro4s8amHX3Fy6txN7+LWdtqZmhkOREISYr4MkLZ18f337i5AgpLd5jw2JWIXu4tvnzCbO54z/ybm42M1d/z54P05f6olS+pI/TV6OzgWc+c1ygFSXKS488HtXwZf+APL8BPXPVh3Hb2+ZIqHfpzypEx5y+Ajg6cZEslZzeNVUyS1KIuWJTBa8Z0pxWXdUkKg+LB5VcLOZEN2kkk8ZyJTkTpk+DDvSPkBt01g22Q+uK5YnnOJK1NUEcwHaDqwgXwQdEA6ZkgCbq15j+ggVu50PlCyYvVmPhpFR9HR3oMYHQNQtalEsSotpIRcCNb8dPlvsPXHi5uLDxfXi2siemZXtKzKihd2F8I2A3ufeGIXCSgPudVW1Ty3lNCcD+TAOeqNbCxtYgwAmiyTeFdPC4za8CyLd9XNzEZRiFhyVYMTOqI71gZGyzSzi238oIF5Joo7S3K7kyabtawswev2oB7FbTS6fnfeqql58WApLRJrXufbRqSWEhpxK1UmdztndSfG01WpxBNq2tk43aeqPpWwmPao1bpH9sYGRk2+E5kFxUNQXAywCkKYx8lGZGlcc5mLArLB8vURysuecK9HSIW0BL/VmhT1nvO8oIP1Qci6YT2D2mChcEiyUvWMQIzcsaEBurGqWd0oy0AwzQzDK6eYGb1EL0RiSf6477Q+fL7TFwrkPaW++78t9j2zl6uEVZziOMl7sv2XdCbXlh6YKFeb8jFWZSP7Joc2AvfUTgxFsRWP+17xp/8nbXyCB/BNQJsNzWDcLfdzI3BMTKJtxb5xgWtOlm/VfRZnQtVxurSoBW1tRjcmjZS8qOMGipzl8E1kkUd6DgkIFAfPnXFmszjoQudlegWT76qbGqlQvbLSuiBokys6SPmKNRnti9lX9kRNYGwEm+IdvT2HZ1NohxKHowv+334pofNc0RKCA+1ukJZJk4Mp0dGjFCZQ97d73WmTstp2doVt78rLBx43VVaylKfxSmTWCSEihaYfefRDa2G7FtIPrbXoyLIp0u4UY+pZ58SB6Lj+a9qsT0OEKhjr4FqbWql71pdv43fO76lQDHzW9VjVUagxIpQexObnTz9ffoJudL34ZfHxBr50bOPdDY4JTBeUnMHfG4eWEd0AEOcQx91hooP4enH1r8VVdNsJ+fHy4+dfF59u4qvLy5tuNaLmOkHcPZByCpsvpGTbTtTOKKFXaYdvqgtWWIZF9nAYpYdECnQMcCmae930J6Exvi4bMzzQshkPlNrc8a2ipan22HtRJFmTUlRMZmZN8vtGSFqbIn4hJIxYkbh26tBDSV2+o0/VLL/ypNYvOVeKrbl+2XDwqSSVU0TW0zpt2zvvIILTQT1qZBavMM1oi2vy5D0GBVXnpCygMdZaomeqBVGhY+5SETofXM+KVJY615/hkYu0ar9/dXPefocGvhRM6w3MEPQezEzK8k7wPWM3oibGFnAyEEqWGb4QcNB8ctfcNWe0gnjj1LGtOOX4dGbGiYMlJ5/TZNYOqrIs6/dZmbBsUyrSNHO0cz6w5C4tS1Izc9vWs6nipmC5zdIZQhOAws5h58Zj8GGd1r3kat19X8kyJxlUDWZdzOPhT1QiRVVjYrAMp0etDfEKJy+0KU6ZvxMk3bsJDWuCjhuSh7CG37W+L83s3pdO0qhzYY9XtYR5pSfQYPauX1B+urn5R2wTl8oVPP90emrK15s3GC1/RNTV4p+fF9c3MVlBEQC1VaiuVsW8wNqVvihqYl1AE6VmErNlKXUIYMh4470a9GpmOGNqIWGftxNufKj5HNM1KimK+ntCXTPY9Zhfl4rRNwX/neRM3jccgDlU9Za6yGn/nDg9IhCwNseQWqoya6hnHcPfo0jrjSFB0YNn9QQPrYKy29Wl1Hpr967yWA3hACuxjo4gRfS+tmqu11AVzFqoc1E+PulfvTppr1BSlhIGmwr8IIq1JrbDM3TQ3TueJs/MPe4bGv36IfGEGV/VZnmoL1XtXG3gpAvftkg0EZ0VglN3w/OLQdU2lNf7SR8oLY9GBrDyIk1voDChsqrKRMLQ3NHTcFPXVTpM1kKzo1d9n+ad9m6yI5Qy5+Pl5d9/XuwpImfBqV7E9Ushzt7WwIwR0GtNOuGeW3j82XU1C7ovABboHSTPzgasZgZekUN1GFXF+rgDB7NVC5j8YQFrsXpNwNRkJjK2QvqHOonO2wB02uv3yWhT59nZ0eF5P3XomrlHFisJxUWT2xCIlm9XdUVXoGd9N362N9rn9k78TJfs5+4a/EO0d9vXt1SaBLtaqwme6Z4vSsFLl8HR5qORKKAD6700tGDfPsk5AniIgTTEqeLhtNv1Ucsb1hB5vXg+NHosY82fagIDkU82TEJTPn0URVo+qqHjBjZizk6WZbo900YEZnLB1LAzsc7WRcbpdcdJ2gu7lf9Yy6J+NOvP1qgoOhIF/gvlA8d/10RvU/HwbkeZZqL7L1wOotsx5GorkmaysJ/oCMTpgE77lT0wExRYOmVyOkAIAeVbNvztYvif8XAWfznUZe3sZGS6spY8NVVal3476JZ3u6nVXfFHjZIjtRTFCBs2xoH+V83Y3AZGD0yO7nF9tMv0+38B")));
$g_SusDBPrio = unserialize(gzinflate(/*1529396483*/base64_decode("RdPLccMwDEXRloQvAaWaLFNDxr1nZOMiCw8wFHX4BFnft6jcvz/39fX5yVSdalN9akzNqWdqzb09VRZEFEjBFFBBFVjBlaJpkiHrZkVWZEVWZEVWZEVWMhsDMGTbMSAbsiEbsiEbspHZyezIjuw7YWRHdmRHdmRHDuRADuRAjn15yJHzpIEcyNHz9pNpJHIiJ3I6m/d/QeZEzmIPcz5kPshHuYR8nJWgyXHOYeWRnxsOmQu5hBUyF3KRuchcZK79NzONInMzjRYaMjdyI3fQkLkPDdPo/y/l2k7mgeTS7Wyv+q7Fdhwg134xV+3VPUP2DNkzZM94f5GfzndfbJfbPWe8d0jtWnPvfJivPw==")));
$g_DeMapper = unserialize(base64_decode("YTo1OntzOjEwOiJ3aXphcmQucGhwIjtzOjM3OiJjbGFzcyBXZWxjb21lU3RlcCBleHRlbmRzIENXaXphcmRTdGVwIjtzOjE3OiJ1cGRhdGVfY2xpZW50LnBocCI7czozNzoieyBDVXBkYXRlQ2xpZW50OjpBZGRNZXNzYWdlMkxvZygiZXhlYyI7czoxMToiaW5jbHVkZS5waHAiO3M6NDg6IkdMT0JBTFNbIlVTRVIiXS0+SXNBdXRob3JpemVkKCkgJiYgJGFyQXV0aFJlc3VsdCI7czo5OiJzdGFydC5waHAiO3M6NjA6IkJYX1JPT1QuJy9tb2R1bGVzL21haW4vY2xhc3Nlcy9nZW5lcmFsL3VwZGF0ZV9kYl91cGRhdGVyLnBocCI7czoxMDoiaGVscGVyLnBocCI7czo1ODoiSlBsdWdpbkhlbHBlcjo6Z2V0UGx1Z2luKCJzeXN0ZW0iLCJvbmVjbGlja2NoZWNrb3V0X3ZtMyIpOyI7fQ=="));

//END_SIG
////////////////////////////////////////////////////////////////////////////
if (!isCli() && !isset($_SERVER['HTTP_USER_AGENT'])) {
  echo "#####################################################\n";
  echo "# Error: cannot run on php-cgi. Requires php as cli #\n";
  echo "#                                                   #\n";
  echo "# See FAQ: http://revisium.com/ai/faq.php           #\n";
  echo "#####################################################\n";
  exit;
}


if (version_compare(phpversion(), '5.3.1', '<')) {
  echo "#####################################################\n";
  echo "# Warning: PHP Version < 5.3.1                      #\n";
  echo "# Some function might not work properly             #\n";
  echo "# See FAQ: http://revisium.com/ai/faq.php           #\n";
  echo "#####################################################\n";
  exit;
}

if (!(function_exists("file_put_contents") && is_callable("file_put_contents"))) {
    echo "#####################################################\n";
	echo "file_put_contents() is disabled. Cannot proceed.\n";
    echo "#####################################################\n";	
    exit;
}
                              
define('AI_VERSION', '20180618');

////////////////////////////////////////////////////////////////////////////

$l_Res = '';

$g_Structure = array();
$g_Counter = 0;

$g_SpecificExt = false;

$g_UpdatedJsonLog = 0;
$g_NotRead = array();
$g_FileInfo = array();
$g_Iframer = array();
$g_PHPCodeInside = array();
$g_CriticalJS = array();
$g_Phishing = array();
$g_Base64 = array();
$g_HeuristicDetected = array();
$g_HeuristicType = array();
$g_UnixExec = array();
$g_SkippedFolders = array();
$g_UnsafeFilesFound = array();
$g_CMS = array();
$g_SymLinks = array();
$g_HiddenFiles = array();
$g_Vulnerable = array();

$g_RegExpStat = array();

$g_TotalFolder = 0;
$g_TotalFiles = 0;

$g_FoundTotalDirs = 0;
$g_FoundTotalFiles = 0;

if (!isCli()) {
   $defaults['site_url'] = 'http://' . $_SERVER['HTTP_HOST'] . '/'; 
}

define('CRC32_LIMIT', pow(2, 31) - 1);
define('CRC32_DIFF', CRC32_LIMIT * 2 -2);

error_reporting(E_ALL ^ E_NOTICE ^ E_WARNING);
srand(time());

set_time_limit(0);
ini_set('max_execution_time', '900000');
ini_set('realpath_cache_size','16M');
ini_set('realpath_cache_ttl','1200');
ini_set('pcre.backtrack_limit','1000000');
ini_set('pcre.recursion_limit','200000');
ini_set('pcre.jit','1');

if (!function_exists('stripos')) {
	function stripos($par_Str, $par_Entry, $Offset = 0) {
		return strpos(strtolower($par_Str), strtolower($par_Entry), $Offset);
	}
}

define('CMS_BITRIX', 'Bitrix');
define('CMS_WORDPRESS', 'Wordpress');
define('CMS_JOOMLA', 'Joomla');
define('CMS_DLE', 'Data Life Engine');
define('CMS_IPB', 'Invision Power Board');
define('CMS_WEBASYST', 'WebAsyst');
define('CMS_OSCOMMERCE', 'OsCommerce');
define('CMS_DRUPAL', 'Drupal');
define('CMS_MODX', 'MODX');
define('CMS_INSTANTCMS', 'Instant CMS');
define('CMS_PHPBB', 'PhpBB');
define('CMS_VBULLETIN', 'vBulletin');
define('CMS_SHOPSCRIPT', 'PHP ShopScript Premium');

define('CMS_VERSION_UNDEFINED', '0.0');

class CmsVersionDetector {
    private $root_path;
    private $versions;
    private $types;

    public function __construct($root_path = '.') {
        $this->root_path = $root_path;
        $this->versions = array();
        $this->types = array();

        $version = '';

        $dir_list = $this->getDirList($root_path);
        $dir_list[] = $root_path;

        foreach ($dir_list as $dir) {
            if ($this->checkBitrix($dir, $version)) {
               $this->addCms(CMS_BITRIX, $version);
            }

            if ($this->checkWordpress($dir, $version)) {
               $this->addCms(CMS_WORDPRESS, $version);
            }

            if ($this->checkJoomla($dir, $version)) {
               $this->addCms(CMS_JOOMLA, $version);
            }

            if ($this->checkDle($dir, $version)) {
               $this->addCms(CMS_DLE, $version);
            }

            if ($this->checkIpb($dir, $version)) {
               $this->addCms(CMS_IPB, $version);
            }

            if ($this->checkWebAsyst($dir, $version)) {
               $this->addCms(CMS_WEBASYST, $version);
            }

            if ($this->checkOsCommerce($dir, $version)) {
               $this->addCms(CMS_OSCOMMERCE, $version);
            }

            if ($this->checkDrupal($dir, $version)) {
               $this->addCms(CMS_DRUPAL, $version);
            }

            if ($this->checkMODX($dir, $version)) {
               $this->addCms(CMS_MODX, $version);
            }

            if ($this->checkInstantCms($dir, $version)) {
               $this->addCms(CMS_INSTANTCMS, $version);
            }

            if ($this->checkPhpBb($dir, $version)) {
               $this->addCms(CMS_PHPBB, $version);
            }

            if ($this->checkVBulletin($dir, $version)) {
               $this->addCms(CMS_VBULLETIN, $version);
            }

            if ($this->checkPhpShopScript($dir, $version)) {
               $this->addCms(CMS_SHOPSCRIPT, $version);
            }

        }
    }

    function getDirList($target) {
       $remove = array('.', '..'); 
       $directories = array_diff(scandir($target), $remove);

       $res = array();
           
       foreach($directories as $value) 
       { 
          if(is_dir($target . '/' . $value)) 
          {
             $res[] = $target . '/' . $value; 
          } 
       }

       return $res;
    }

    function isCms($name, $version) {
		for ($i = 0; $i < count($this->types); $i++) {
			if ((strpos($this->types[$i], $name) !== false) 
				&& 
			    (strpos($this->versions[$i], $version) !== false)) {
				return true;
			}
		}
    	
		return false;
    }

    function getCmsList() {
      return $this->types;
    }

    function getCmsVersions() {
      return $this->versions;
    }

    function getCmsNumber() {
      return count($this->types);
    }

    function getCmsName($index = 0) {
      return $this->types[$index];
    }

    function getCmsVersion($index = 0) {
      return $this->versions[$index];
    }

    private function addCms($type, $version) {
       $this->types[] = $type;
       $this->versions[] = $version;
    }

    private function checkBitrix($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir .'/bitrix')) {
          $res = true;

          $tmp_content = @file_get_contents($this->root_path .'/bitrix/modules/main/classes/general/version.php');
          if (preg_match('|define\("SM_VERSION","(.+?)"\)|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

       }

       return $res;
    }

    private function checkWordpress($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir .'/wp-admin')) {
          $res = true;

          $tmp_content = @file_get_contents($dir .'/wp-includes/version.php');
          if (preg_match('|\$wp_version\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }
       }

       return $res;
    }

    private function checkJoomla($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir .'/libraries/joomla')) {
          $res = true;

          // for 1.5.x
          $tmp_content = @file_get_contents($dir .'/libraries/joomla/version.php');
          if (preg_match('|var\s+\$RELEASE\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];

             if (preg_match('|var\s+\$DEV_LEVEL\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version .= '.' . $tmp_ver[1];
             }
          }

          // for 1.7.x
          $tmp_content = @file_get_contents($dir .'/includes/version.php');
          if (preg_match('|public\s+\$RELEASE\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];

             if (preg_match('|public\s+\$DEV_LEVEL\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version .= '.' . $tmp_ver[1];
             }
          }


	  // for 2.5.x and 3.x 
          $tmp_content = @file_get_contents($dir . '/libraries/cms/version/version.php');
   
          if (preg_match('|const\s+RELEASE\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
	      $version = $tmp_ver[1];
 
             if (preg_match('|const\s+DEV_LEVEL\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) { 
		$version .= '.' . $tmp_ver[1];
             }
          }

       }

       return $res;
    }

    private function checkDle($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir .'/engine/engine.php')) {
          $res = true;

          $tmp_content = @file_get_contents($dir . '/engine/data/config.php');
          if (preg_match('|\'version_id\'\s*=>\s*"(.+?)"|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

          $tmp_content = @file_get_contents($dir . '/install.php');
          if (preg_match('|\'version_id\'\s*=>\s*"(.+?)"|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

       }

       return $res;
    }

    private function checkIpb($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir . '/ips_kernel')) {
          $res = true;

          $tmp_content = @file_get_contents($dir . '/ips_kernel/class_xml.php');
          if (preg_match('|IP.Board\s+v([0-9\.]+)|si', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

       }

       return $res;
    }

    private function checkWebAsyst($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir . '/wbs/installer')) {
          $res = true;

          $tmp_content = @file_get_contents($dir . '/license.txt');
          if (preg_match('|v([0-9\.]+)|si', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

       }

       return $res;
    }

    private function checkOsCommerce($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir . '/includes/version.php')) {
          $res = true;

          $tmp_content = @file_get_contents($dir . '/includes/version.php');
          if (preg_match('|([0-9\.]+)|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

       }

       return $res;
    }

    private function checkDrupal($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir . '/sites/all')) {
          $res = true;

          $tmp_content = @file_get_contents($dir . '/CHANGELOG.txt');
          if (preg_match('|Drupal\s+([0-9\.]+)|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

       }

       if (file_exists($dir . '/core/lib/Drupal.php')) {
          $res = true;

          $tmp_content = @file_get_contents($dir . '/core/lib/Drupal.php');
          if (preg_match('|VERSION\s*=\s*\'(\d+\.\d+\.\d+)\'|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

       }

       if (file_exists($dir . 'modules/system/system.info')) {
          $res = true;

          $tmp_content = @file_get_contents($dir . 'modules/system/system.info');
          if (preg_match('|version\s*=\s*"\d+\.\d+"|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

       }

       return $res;
    }

    private function checkMODX($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir . '/manager/assets')) {
          $res = true;

          // no way to pick up version
       }

       return $res;
    }

    private function checkInstantCms($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir . '/plugins/p_usertab')) {
          $res = true;

          $tmp_content = @file_get_contents($dir . '/index.php');
          if (preg_match('|InstantCMS\s+v([0-9\.]+)|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

       }

       return $res;
    }

    private function checkPhpBb($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir . '/includes/acp')) {
          $res = true;

          $tmp_content = @file_get_contents($dir . '/config.php');
          if (preg_match('|phpBB\s+([0-9\.x]+)|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

       }

       return $res;
    }

    private function checkVBulletin($dir, &$version) {
          $version = CMS_VERSION_UNDEFINED;
          $res = false;
          if (file_exists($dir . '/core/includes/md5_sums_vbulletin.php'))
          {
                $res = true;
                require_once($dir . '/core/includes/md5_sums_vbulletin.php');
                $version = $md5_sum_versions['vb5_connect'];
          }
          else if(file_exists($dir . '/includes/md5_sums_vbulletin.php'))
          {
                $res = true;
                require_once($dir . '/includes/md5_sums_vbulletin.php');
                $version = $md5_sum_versions['vbulletin'];
          }
          return $res;
       }

    private function checkPhpShopScript($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir . '/install/consts.php')) {
          $res = true;

          $tmp_content = @file_get_contents($dir . '/install/consts.php');
          if (preg_match('|STRING_VERSION\',\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

       }

       return $res;
    }
}

/**
 * Print file
*/
function printFile() {
	$l_FileName = $_GET['fn'];
	$l_CRC = isset($_GET['c']) ? (int)$_GET['c'] : 0;
	$l_Content = file_get_contents($l_FileName);
	$l_FileCRC = realCRC($l_Content);
	if ($l_FileCRC != $l_CRC) {
		echo 'Доступ запрещен.';
		exit;
	}
	
	echo '<pre>' . htmlspecialchars($l_Content) . '</pre>';
}

/**
 *
 */
function realCRC($str_in, $full = false)
{
        $in = crc32( $full ? normal($str_in) : $str_in );
        return ($in > CRC32_LIMIT) ? ($in - CRC32_DIFF) : $in;
}


/**
 * Determine php script is called from the command line interface
 * @return bool
 */
function isCli()
{
	return php_sapi_name() == 'cli';
}

function myCheckSum($str) {
   return hash('crc32b', $str);
}

 function generatePassword ($length = 9)
  {

    // start with a blank password
    $password = "";

    // define possible characters - any character in this string can be
    // picked for use in the password, so if you want to put vowels back in
    // or add special characters such as exclamation marks, this is where
    // you should do it
    $possible = "2346789bcdfghjkmnpqrtvwxyzBCDFGHJKLMNPQRTVWXYZ";

    // we refer to the length of $possible a few times, so let's grab it now
    $maxlength = strlen($possible);
  
    // check for length overflow and truncate if necessary
    if ($length > $maxlength) {
      $length = $maxlength;
    }
	
    // set up a counter for how many characters are in the password so far
    $i = 0; 
    
    // add random characters to $password until $length is reached
    while ($i < $length) { 

      // pick a random character from the possible ones
      $char = substr($possible, mt_rand(0, $maxlength-1), 1);
        
      // have we already used this character in $password?
      if (!strstr($password, $char)) { 
        // no, so it's OK to add it onto the end of whatever we've already got...
        $password .= $char;
        // ... and increase the counter by one
        $i++;
      }

    }

    // done!
    return $password;

  }

/**
 * Print to console
 * @param mixed $text
 * @param bool $add_lb Add line break
 * @return void
 */
function stdOut($text, $add_lb = true)
{
	if (!isCli())
		return;
		
	if (is_bool($text))
	{
		$text = $text ? 'true' : 'false';
	}
	else if (is_null($text))
	{
		$text = 'null';
	}
	if (!is_scalar($text))
	{
		$text = print_r($text, true);
	}

 	if (!BOOL_RESULT)
 	{
 		@fwrite(STDOUT, $text . ($add_lb ? "\n" : ''));
 	}
}

/**
 * Print progress
 * @param int $num Current file
 */
function printProgress($num, &$par_File)
{
	global $g_CriticalPHP, $g_Base64, $g_Phishing, $g_CriticalJS, $g_Iframer, $g_UpdatedJsonLog, 
               $g_AddPrefix, $g_NoPrefix;

	$total_files = $GLOBALS['g_FoundTotalFiles'];
	$elapsed_time = microtime(true) - START_TIME;
	$percent = number_format($total_files ? $num * 100 / $total_files : 0, 1);
	$stat = '';
	if ($elapsed_time >= 1)
	{
		$elapsed_seconds = round($elapsed_time, 0);
		$fs = floor($num / $elapsed_seconds);
		$left_files = $total_files - $num;
		if ($fs > 0) 
		{
		   $left_time = ($left_files / $fs); //ceil($left_files / $fs);
		   $stat = ' [Avg: ' . round($fs,2) . ' files/s' . ($left_time > 0  ? ' Left: ' . seconds2Human($left_time) : '') . '] [Mlw:' . (count($g_CriticalPHP) + count($g_Base64))  . '|' . (count($g_CriticalJS) + count($g_Iframer) + count($g_Phishing)) . ']';
        }
	}

        $l_FN = $g_AddPrefix . str_replace($g_NoPrefix, '', $par_File); 
	$l_FN = substr($par_File, -60);

	$text = "$percent% [$l_FN] $num of {$total_files}. " . $stat;
	$text = str_pad($text, 160, ' ', STR_PAD_RIGHT);
	stdOut(str_repeat(chr(8), 160) . $text, false);


      	$data = array('self' => __FILE__, 'started' => AIBOLIT_START_TIME, 'updated' => time(), 
                            'progress' => $percent, 'time_elapsed' => $elapsed_seconds, 
                            'time_left' => round($left_time), 'files_left' => $left_files, 
                            'files_total' => $total_files, 'current_file' => substr($g_AddPrefix . str_replace($g_NoPrefix, '', $par_File), -160));

        if (function_exists('aibolit_onProgressUpdate')) { aibolit_onProgressUpdate($data); }

	if (defined('PROGRESS_LOG_FILE') && 
           (time() - $g_UpdatedJsonLog > 1)) {
                if (function_exists('json_encode')) {
             	   file_put_contents(PROGRESS_LOG_FILE, json_encode($data));
                } else {
             	   file_put_contents(PROGRESS_LOG_FILE, serialize($data));
                }

		$g_UpdatedJsonLog = time();
        }
}

/**
 * Seconds to human readable
 * @param int $seconds
 * @return string
 */
function seconds2Human($seconds)
{
	$r = '';
	$_seconds = floor($seconds);
	$ms = $seconds - $_seconds;
	$seconds = $_seconds;
	if ($hours = floor($seconds / 3600))
	{
		$r .= $hours . (isCli() ? ' h ' : ' час ');
		$seconds = $seconds % 3600;
	}

	if ($minutes = floor($seconds / 60))
	{
		$r .= $minutes . (isCli() ? ' m ' : ' мин ');
		$seconds = $seconds % 60;
	}

	if ($minutes < 3) $r .= ' ' . $seconds + ($ms > 0 ? round($ms) : 0) . (isCli() ? ' s' : ' сек'); 

	return $r;
}

if (isCli())
{

	$cli_options = array(
                'y' => 'deobfuscate',
                'c:' => 'avdb:',
		'm:' => 'memory:',
		's:' => 'size:',
		'a' => 'all',
		'd:' => 'delay:',
		'l:' => 'list:',
		'r:' => 'report:',
		'f' => 'fast',
		'j:' => 'file:',
		'p:' => 'path:',
		'q' => 'quite',
		'e:' => 'cms:',
		'x:' => 'mode:',
		'k:' => 'skip:',
		'i:' => 'idb:',
		'n' => 'sc',
		'o:' => 'json_report:',
		't:' => 'php_report:',
		'z:' => 'progress:',
		'g:' => 'handler:',
		'b' => 'smart',
		'u:' => 'username:',
		'h' => 'help',
	);

	$cli_longopts = array(
                'deobfuscate',
		'avdb:',
		'cmd:',
		'noprefix:',
		'addprefix:',
		'scan:',
		'one-pass',
		'smart',
		'quarantine',
		'with-2check',
		'skip-cache',
		'username:', 
		'imake',
		'icheck'
	);
	
	$cli_longopts = array_merge($cli_longopts, array_values($cli_options));

	$options = getopt(implode('', array_keys($cli_options)), $cli_longopts);

	if (isset($options['h']) OR isset($options['help']))
	{
		$memory_limit = ini_get('memory_limit');
		echo <<<HELP
Revisium AI-Bolit - Intelligent Malware File Scanner for Websites.

Usage: php {$_SERVER['PHP_SELF']} [OPTIONS] [PATH]
Current default path is: {$defaults['path']}

  -j, --file=FILE      		Full path to single file to check
  -l, --list=FILE      		Full path to create plain text file with a list of found malware
  -o, --json_report=FILE	Full path to create json-file with a list of found malware
  -p, --path=PATH      		Directory path to scan, by default the file directory is used
                       		Current path: {$defaults['path']}
  -m, --memory=SIZE    		Maximum amount of memory a script may consume. Current value: $memory_limit
                       		Can take shorthand byte values (1M, 1G...)
  -s, --size=SIZE      		Scan files are smaller than SIZE. 0 - All files. Current value: {$defaults['max_size_to_scan']}
  -a, --all            		Scan all files (by default scan. js,. php,. html,. htaccess)
  -d, --delay=INT      		Delay in milliseconds when scanning files to reduce load on the file system (Default: 1)
  -x, --mode=INT       		Set scan mode. 0 - for basic, 1 - for expert and 2 for paranoic.
  -k, --skip=jpg,...   		Skip specific extensions. E.g. --skip=jpg,gif,png,xls,pdf
      --scan=php,...   		Scan only specific extensions. E.g. --scan=php,htaccess,js
  -r, --report=PATH/EMAILS
  -z, --progress=FILE  		Runtime progress of scanning, saved to the file, full path required. 
  -u, --username=<username>  	Run scanner with specific user id and group id, e.g. --username=www-data
  -g, --hander=FILE    		External php handler for different events, full path to php file required.
      --cmd="command [args...]"
      --smart                   Enable smart mode (skip cache files and optimize scanning)
                       		Run command after scanning
      --one-pass       		Do not calculate remaining time
      --quarantine     		Archive all malware from report
      --with-2check    		Create or use AI-BOLIT-DOUBLECHECK.php file
      --imake
      --icheck
      --idb=file	   	Integrity Check database file

      --help           		Display this help and exit

* Mandatory arguments listed below are required for both full and short way of usage.

HELP;
		exit;
	}

	$l_FastCli = false;
	
	if (
		(isset($options['memory']) AND !empty($options['memory']) AND ($memory = $options['memory']))
		OR (isset($options['m']) AND !empty($options['m']) AND ($memory = $options['m']))
	)
	{
		$memory = getBytes($memory);
		if ($memory > 0)
		{
			$defaults['memory_limit'] = $memory;
			ini_set('memory_limit', $memory);
		}
	}


	$avdb = '';
	if (
		(isset($options['avdb']) AND !empty($options['avdb']) AND ($avdb = $options['avdb']))
		OR (isset($options['c']) AND !empty($options['c']) AND ($avdb = $options['c']))
	)
	{
		if (file_exists($avdb))
		{
			$defaults['avdb'] = $avdb;
		}
	}

	if (
		(isset($options['file']) AND !empty($options['file']) AND ($file = $options['file']) !== false)
		OR (isset($options['j']) AND !empty($options['j']) AND ($file = $options['j']) !== false)
	)
	{
		define('SCAN_FILE', $file);
	}


	if (isset($options['deobfuscate']) OR isset($options['y']))
	{
		define('AI_DEOBFUSCATE', true);
	}

	if (
		(isset($options['list']) AND !empty($options['list']) AND ($file = $options['list']) !== false)
		OR (isset($options['l']) AND !empty($options['l']) AND ($file = $options['l']) !== false)
	)
	{

		define('PLAIN_FILE', $file);
	}

	if (
		(isset($options['json_report']) AND !empty($options['json_report']) AND ($file = $options['json_report']) !== false)
		OR (isset($options['o']) AND !empty($options['o']) AND ($file = $options['o']) !== false)
	)
	{
		define('JSON_FILE', $file);
	}

	if (
		(isset($options['php_report']) AND !empty($options['php_report']) AND ($file = $options['php_report']) !== false)
		OR (isset($options['t']) AND !empty($options['t']) AND ($file = $options['t']) !== false)
	)
	{
		define('PHP_FILE', $file);
	}

	if (isset($options['smart']) OR isset($options['b']))
	{
		define('SMART_SCAN', 1);
	}

	if (
		(isset($options['handler']) AND !empty($options['handler']) AND ($file = $options['handler']) !== false)
		OR (isset($options['g']) AND !empty($options['g']) AND ($file = $options['g']) !== false)
	)
	{
	        if (file_exists($file)) {
		   define('AIBOLIT_EXTERNAL_HANDLER', $file);
                }
	}

	if (
		(isset($options['progress']) AND !empty($options['progress']) AND ($file = $options['progress']) !== false)
		OR (isset($options['z']) AND !empty($options['z']) AND ($file = $options['z']) !== false)
	)
	{
		define('PROGRESS_LOG_FILE', $file);
	}

	if (
		(isset($options['size']) AND !empty($options['size']) AND ($size = $options['size']) !== false)
		OR (isset($options['s']) AND !empty($options['s']) AND ($size = $options['s']) !== false)
	)
	{
		$size = getBytes($size);
		$defaults['max_size_to_scan'] = $size > 0 ? $size : 0;
	}

	if (
		(isset($options['username']) AND !empty($options['username']) AND ($username = $options['username']) !== false)
		OR (isset($options['u']) AND !empty($options['u']) AND ($username = $options['u']) !== false)
	)
	{

                if (!empty($username) && ($info = posix_getpwnam($username)) !== false) {
                    posix_setgid($info['gid']);
                    posix_setuid($info['uid']);
                    $defaults['userid'] = $info['uid'];
                    $defaults['groupid'] = $info['gid'];
                } else {
                    echo('Invalid username');
                    exit(-1);
                }               
	}

 	if (
 		(isset($options['file']) AND !empty($options['file']) AND ($file = $options['file']) !== false)
 		OR (isset($options['j']) AND !empty($options['j']) AND ($file = $options['j']) !== false)
 		AND (isset($options['q'])) 
 	
 	)
 	{
 		$BOOL_RESULT = true;
 	}
 
	if (isset($options['f'])) 
	{
	   $l_FastCli = true;
	}
		
	if (isset($options['q']) || isset($options['quite'])) 
	{
 	    $BOOL_RESULT = true;
	}

        if (isset($options['x'])) {
            define('AI_EXPERT', $options['x']);
        } else if (isset($options['mode'])) {
            define('AI_EXPERT', $options['mode']);
        } else {
            define('AI_EXPERT', AI_EXPERT_MODE); 
        }

        if (AI_EXPERT < 2) {
           $g_SpecificExt = true;
           $defaults['scan_all_files'] = false;
        } else {
           $defaults['scan_all_files'] = true;
        }	

	define('BOOL_RESULT', $BOOL_RESULT);

	if (
		(isset($options['delay']) AND !empty($options['delay']) AND ($delay = $options['delay']) !== false)
		OR (isset($options['d']) AND !empty($options['d']) AND ($delay = $options['d']) !== false)
	)
	{
		$delay = (int) $delay;
		if (!($delay < 0))
		{
			$defaults['scan_delay'] = $delay;
		}
	}

	if (
		(isset($options['skip']) AND !empty($options['skip']) AND ($ext_list = $options['skip']) !== false)
		OR (isset($options['k']) AND !empty($options['k']) AND ($ext_list = $options['k']) !== false)
	)
	{
		$defaults['skip_ext'] = $ext_list;
	}

	if (isset($options['n']) OR isset($options['skip-cache']))
	{
		$defaults['skip_cache'] = true;
	}

	if (isset($options['scan']))
	{
		$ext_list = strtolower(trim($options['scan'], " ,\t\n\r\0\x0B"));
		if ($ext_list != '')
		{
			$l_FastCli = true;
			$g_SensitiveFiles = explode(",", $ext_list);
			for ($i = 0; $i < count($g_SensitiveFiles); $i++) {
			   if ($g_SensitiveFiles[$i] == '.') {
                              $g_SensitiveFiles[$i] = '';
                           }
                        }

			$g_SpecificExt = true;
		}
	}


    if (isset($options['all']) OR isset($options['a']))
    {
    	$defaults['scan_all_files'] = true;
        $g_SpecificExt = false;
    }

    if (isset($options['cms'])) {
        define('CMS', $options['cms']);
    } else if (isset($options['e'])) {
        define('CMS', $options['e']);
    }


    if (!defined('SMART_SCAN')) {
       define('SMART_SCAN', 1);
    }

    if (!defined('AI_DEOBFUSCATE')) {
       define('AI_DEOBFUSCATE', false);
    }


	$l_SpecifiedPath = false;
	if (
		(isset($options['path']) AND !empty($options['path']) AND ($path = $options['path']) !== false)
		OR (isset($options['p']) AND !empty($options['p']) AND ($path = $options['p']) !== false)
	)
	{
		$defaults['path'] = $path;
		$l_SpecifiedPath = true;
	}

	if (
		isset($options['noprefix']) AND !empty($options['noprefix']) AND ($g_NoPrefix = $options['noprefix']) !== false)
		
	{
	} else {
		$g_NoPrefix = '';
	}

	if (
		isset($options['addprefix']) AND !empty($options['addprefix']) AND ($g_AddPrefix = $options['addprefix']) !== false)
		
	{
	} else {
		$g_AddPrefix = '';
	}



	$l_SuffixReport = str_replace('/var/www', '', $defaults['path']);
	$l_SuffixReport = str_replace('/home', '', $l_SuffixReport);
        $l_SuffixReport = preg_replace('#[/\\\.\s]#', '_', $l_SuffixReport);
	$l_SuffixReport .=  "-" . rand(1, 999999);
		
	if (
		(isset($options['report']) AND ($report = $options['report']) !== false)
		OR (isset($options['r']) AND ($report = $options['r']) !== false)
	)
	{
		$report = str_replace('@PATH@', $l_SuffixReport, $report);
		$report = str_replace('@RND@', rand(1, 999999), $report);
		$report = str_replace('@DATE@', date('d-m-Y-h-i'), $report);
		define('REPORT', $report);
		define('NEED_REPORT', true);
	}

	if (
		(isset($options['idb']) AND ($ireport = $options['idb']) !== false)
	)
	{
		$ireport = str_replace('@PATH@', $l_SuffixReport, $ireport);
		$ireport = str_replace('@RND@', rand(1, 999999), $ireport);
		$ireport = str_replace('@DATE@', date('d-m-Y-h-i'), $ireport);
		define('INTEGRITY_DB_FILE', $ireport);
	}

  
	defined('REPORT') OR define('REPORT', 'AI-BOLIT-REPORT-' . $l_SuffixReport . '-' . date('d-m-Y_H-i') . '.html');
	
	defined('INTEGRITY_DB_FILE') OR define('INTEGRITY_DB_FILE', 'AINTEGRITY-' . $l_SuffixReport . '-' . date('d-m-Y_H-i'));

	$last_arg = max(1, sizeof($_SERVER['argv']) - 1);
	if (isset($_SERVER['argv'][$last_arg]))
	{
		$path = $_SERVER['argv'][$last_arg];
		if (
			substr($path, 0, 1) != '-'
			AND (substr($_SERVER['argv'][$last_arg - 1], 0, 1) != '-' OR array_key_exists(substr($_SERVER['argv'][$last_arg - 1], -1), $cli_options)))
		{
			$defaults['path'] = $path;
		}
	}	
	
	
	define('ONE_PASS', isset($options['one-pass']));

	define('IMAKE', isset($options['imake']));
	define('ICHECK', isset($options['icheck']));

	if (IMAKE && ICHECK) die('One of the following options must be used --imake or --icheck.');

} else {
   define('AI_EXPERT', AI_EXPERT_MODE); 
   define('ONE_PASS', true);
}


if (isset($defaults['avdb']) && file_exists($defaults['avdb'])) {
   $avdb = explode("\n", gzinflate(base64_decode(str_rot13(strrev(trim(file_get_contents($defaults['avdb'])))))));

   $g_DBShe = explode("\n", base64_decode($avdb[0]));
   $gX_DBShe = explode("\n", base64_decode($avdb[1]));
   $g_FlexDBShe = explode("\n", base64_decode($avdb[2]));
   $gX_FlexDBShe = explode("\n", base64_decode($avdb[3]));
   $gXX_FlexDBShe = explode("\n", base64_decode($avdb[4]));
   $g_ExceptFlex = explode("\n", base64_decode($avdb[5]));
   $g_AdwareSig = explode("\n", base64_decode($avdb[6]));
   $g_PhishingSig = explode("\n", base64_decode($avdb[7]));
   $g_JSVirSig = explode("\n", base64_decode($avdb[8]));
   $gX_JSVirSig = explode("\n", base64_decode($avdb[9]));
   $g_SusDB = explode("\n", base64_decode($avdb[10]));
   $g_SusDBPrio = explode("\n", base64_decode($avdb[11]));
   $g_DeMapper = array_combine(explode("\n", base64_decode($avdb[12])), explode("\n", base64_decode($avdb[13])));

   if (count($g_DBShe) <= 1) {
      $g_DBShe = array();
   }

   if (count($gX_DBShe) <= 1) {
      $gX_DBShe = array();
   }

   if (count($g_FlexDBShe) <= 1) {
      $g_FlexDBShe = array();
   }

   if (count($gX_FlexDBShe) <= 1) {
      $gX_FlexDBShe = array();
   }

   if (count($gXX_FlexDBShe) <= 1) {
      $gXX_FlexDBShe = array();
   }

   if (count($g_ExceptFlex) <= 1) {
      $g_ExceptFlex = array();
   }

   if (count($g_AdwareSig) <= 1) {
      $g_AdwareSig = array();
   }

   if (count($g_PhishingSig) <= 1) {
      $g_PhishingSig = array();
   }

   if (count($gX_JSVirSig) <= 1) {
      $gX_JSVirSig = array();
   }

   if (count($g_JSVirSig) <= 1) {
      $g_JSVirSig = array();
   }

   if (count($g_SusDB) <= 1) {
      $g_SusDB = array();
   }

   if (count($g_SusDBPrio) <= 1) {
      $g_SusDBPrio = array();
   }

   stdOut('Loaded external signatures from ' . $defaults['avdb']);
}

// use only basic signature subset
if (AI_EXPERT < 2) {
   $gX_FlexDBShe = array();
   $gXX_FlexDBShe = array();
   $gX_JSVirSig = array();
}

if (isset($defaults['userid'])) {
   stdOut('Running from ' . $defaults['userid'] . ':' . $defaults['groupid']);
}

stdOut('Malware signatures: ' . (count($g_JSVirSig) + count($gX_JSVirSig) + count($g_DBShe) + count($gX_DBShe) + count($gX_DBShe) + count($g_FlexDBShe) + count($gX_FlexDBShe) + count($gXX_FlexDBShe)));

if ($g_SpecificExt) {
  stdOut("Scan specific extensions: " . implode(',', $g_SensitiveFiles));
}

if (!DEBUG_PERFORMANCE) {
   OptimizeSignatures();
} else {
   stdOut("Debug Performance Scan");
}

$g_DBShe  = array_map('strtolower', $g_DBShe);
$gX_DBShe = array_map('strtolower', $gX_DBShe);

if (!defined('PLAIN_FILE')) { define('PLAIN_FILE', ''); }

// Init
define('MAX_ALLOWED_PHP_HTML_IN_DIR', 600);
define('BASE64_LENGTH', 69);
define('MAX_PREVIEW_LEN', 120);
define('MAX_EXT_LINKS', 1001);

if (defined('AIBOLIT_EXTERNAL_HANDLER')) {
   include_once(AIBOLIT_EXTERNAL_HANDLER);
   stdOut("\nLoaded external handler: " . AIBOLIT_EXTERNAL_HANDLER . "\n");
   if (function_exists("aibolit_onStart")) { aibolit_onStart(); }
}

// Perform full scan when running from command line
if (isset($_GET['full'])) {
  $defaults['scan_all_files'] = 1;
}

if ($l_FastCli) {
  $defaults['scan_all_files'] = 0; 
}

if (!isCli()) {
  	define('ICHECK', isset($_GET['icheck']));
  	define('IMAKE', isset($_GET['imake']));
	
	define('INTEGRITY_DB_FILE', 'ai-integrity-db');
}

define('SCAN_ALL_FILES', (bool) $defaults['scan_all_files']);
define('SCAN_DELAY', (int) $defaults['scan_delay']);
define('MAX_SIZE_TO_SCAN', getBytes($defaults['max_size_to_scan']));

if ($defaults['memory_limit'] AND ($defaults['memory_limit'] = getBytes($defaults['memory_limit'])) > 0) {
	ini_set('memory_limit', $defaults['memory_limit']);
    stdOut("Changed memory limit to " . $defaults['memory_limit']);
}

define('ROOT_PATH', realpath($defaults['path']));

if (!ROOT_PATH)
{
    if (isCli())  {
		die(stdOut("Directory '{$defaults['path']}' not found!"));
	}
}
elseif(!is_readable(ROOT_PATH))
{
        if (isCli())  {
		die2(stdOut("Cannot read directory '" . ROOT_PATH . "'!"));
	}
}

define('CURRENT_DIR', getcwd());
chdir(ROOT_PATH);

if (isCli() AND REPORT !== '' AND !getEmails(REPORT))
{
	$report = str_replace('\\', '/', REPORT);
	$abs = strpos($report, '/') === 0 ? DIR_SEPARATOR : '';
	$report = array_values(array_filter(explode('/', $report)));
	$report_file = array_pop($report);
	$report_path = realpath($abs . implode(DIR_SEPARATOR, $report));

	define('REPORT_FILE', $report_file);
	define('REPORT_PATH', $report_path);

	if (REPORT_FILE AND REPORT_PATH AND is_file(REPORT_PATH . DIR_SEPARATOR . REPORT_FILE))
	{
		@unlink(REPORT_PATH . DIR_SEPARATOR . REPORT_FILE);
	}
}

if (defined('REPORT_PATH')) {
   $l_ReportDirName = REPORT_PATH;
}

define('QUEUE_FILENAME', ($l_ReportDirName != '' ? $l_ReportDirName . '/' : '') . 'AI-BOLIT-QUEUE-' . md5($defaults['path']) . '-' . rand(1000,9999) . '.txt');

if (function_exists('phpinfo')) {
   ob_start();
   phpinfo();
   $l_PhpInfo = ob_get_contents();
   ob_end_clean();

   $l_PhpInfo = str_replace('border: 1px', '', $l_PhpInfo);
   preg_match('|<body>(.*)</body>|smi', $l_PhpInfo, $l_PhpInfoBody);
}

////////////////////////////////////////////////////////////////////////////
$l_Template = str_replace("@@MODE@@", AI_EXPERT . '/' . SMART_SCAN, $l_Template);

if (AI_EXPERT == 0) {
   $l_Result .= '<div class="rep">' . AI_STR_057 . '</div>'; 
} else {
}

$l_Template = str_replace('@@HEAD_TITLE@@', AI_STR_051 . $g_AddPrefix . str_replace($g_NoPrefix, '', ROOT_PATH), $l_Template);

define('QCR_INDEX_FILENAME', 'fn');
define('QCR_INDEX_TYPE', 'type');
define('QCR_INDEX_WRITABLE', 'wr');
define('QCR_SVALUE_FILE', '1');
define('QCR_SVALUE_FOLDER', '0');

/**
 * Extract emails from the string
 * @param string $email
 * @return array of strings with emails or false on error
 */
function getEmails($email)
{
	$email = preg_split('#[,\s;]#', $email, -1, PREG_SPLIT_NO_EMPTY);
	$r = array();
	for ($i = 0, $size = sizeof($email); $i < $size; $i++)
	{
	        if (function_exists('filter_var')) {
   		   if (filter_var($email[$i], FILTER_VALIDATE_EMAIL))
   		   {
   		   	$r[] = $email[$i];
    		   }
                } else {
                   // for PHP4
                   if (strpos($email[$i], '@') !== false) {
   		   	$r[] = $email[$i];
                   }
                }
	}
	return empty($r) ? false : $r;
}

/**
 * Get bytes from shorthand byte values (1M, 1G...)
 * @param int|string $val
 * @return int
 */
function getBytes($val)
{
	$val = trim($val);
	$last = strtolower($val{strlen($val) - 1});
	switch($last) {
		case 't':
			$val *= 1024;
		case 'g':
			$val *= 1024;
		case 'm':
			$val *= 1024;
		case 'k':
			$val *= 1024;
	}
	return intval($val);
}

/**
 * Format bytes to human readable
 * @param int $bites
 * @return string
 */
function bytes2Human($bites)
{
	if ($bites < 1024)
	{
		return $bites . ' b';
	}
	elseif (($kb = $bites / 1024) < 1024)
	{
		return number_format($kb, 2) . ' Kb';
	}
	elseif (($mb = $kb / 1024) < 1024)
	{
		return number_format($mb, 2) . ' Mb';
	}
	elseif (($gb = $mb / 1024) < 1024)
	{
		return number_format($gb, 2) . ' Gb';
	}
	else
	{
		return number_format($gb / 1024, 2) . 'Tb';
	}
}

///////////////////////////////////////////////////////////////////////////
function needIgnore($par_FN, $par_CRC) {
  global $g_IgnoreList;
  
  for ($i = 0; $i < count($g_IgnoreList); $i++) {
     if (strpos($par_FN, $g_IgnoreList[$i][0]) !== false) {
		if ($par_CRC == $g_IgnoreList[$i][1]) {
			return true;
		}
	 }
  }
  
  return false;
}

///////////////////////////////////////////////////////////////////////////
function makeSafeFn($par_Str, $replace_path = false) {
  global $g_AddPrefix, $g_NoPrefix;
  if ($replace_path) {
     $lines = explode("\n", $par_Str);
     array_walk($lines, function(&$n) {
          global $g_AddPrefix, $g_NoPrefix;
          $n = $g_AddPrefix . str_replace($g_NoPrefix, '', $n); 
     }); 

     $par_Str = implode("\n", $lines);
  }
 
  return htmlspecialchars($par_Str, ENT_SUBSTITUTE | ENT_QUOTES);
}

function replacePathArray($par_Arr) {
  global $g_AddPrefix, $g_NoPrefix;
     array_walk($par_Arr, function(&$n) {
          global $g_AddPrefix, $g_NoPrefix;
          $n = $g_AddPrefix . str_replace($g_NoPrefix, '', $n); 
     }); 

  return $par_Arr;
}

///////////////////////////////////////////////////////////////////////////
function getRawJsonVuln($par_List) {
  global $g_Structure, $g_NoPrefix, $g_AddPrefix;
   $results = array();
   $l_Src = array('&quot;', '&lt;', '&gt;', '&amp;', '&#039;', '<' . '?php.');
   $l_Dst = array('"',      '<',    '>',    '&', '\'',         '<' . '?php ');

   for ($i = 0; $i < count($par_List); $i++) {
      $l_Pos = $par_List[$i]['ndx'];
      $res['fn'] = $g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$l_Pos]);
      $res['sig'] = $par_List[$i]['id'];

      $res['ct'] = $g_Structure['c'][$l_Pos];
      $res['mt'] = $g_Structure['m'][$l_Pos];
      $res['sz'] = $g_Structure['s'][$l_Pos];
      $res['sigid'] = 'vuln_' . md5($g_Structure['n'][$l_Pos] . $par_List[$i]['id']);

      $results[] = $res; 
   }

   return $results;
}

///////////////////////////////////////////////////////////////////////////
function getRawJson($par_List, $par_Details = null, $par_SigId = null) {
  global $g_Structure, $g_NoPrefix, $g_AddPrefix;
   $results = array();
   $l_Src = array('&quot;', '&lt;', '&gt;', '&amp;', '&#039;', '<' . '?php.');
   $l_Dst = array('"',      '<',    '>',    '&', '\'',         '<' . '?php ');

   for ($i = 0; $i < count($par_List); $i++) {
       if ($par_SigId != null) {
          $l_SigId = 'id_' . $par_SigId[$i];
       } else {
          $l_SigId = 'id_n' . rand(1000000, 9000000);
       }
       


      $l_Pos = $par_List[$i];
      $res['fn'] = $g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$l_Pos]);
      if ($par_Details != null) {
         $res['sig'] = preg_replace('|(L\d+).+__AI_MARKER__|smi', '[$1]: ...', $par_Details[$i]);
         $res['sig'] = preg_replace('/[^\x20-\x7F]/', '.', $res['sig']);
         $res['sig'] = preg_replace('/__AI_LINE1__(\d+)__AI_LINE2__/', '[$1] ', $res['sig']);
         $res['sig'] = preg_replace('/__AI_MARKER__/', ' @!!!>', $res['sig']);
         $res['sig'] = str_replace($l_Src, $l_Dst, $res['sig']);
      }

      $res['ct'] = $g_Structure['c'][$l_Pos];
      $res['mt'] = $g_Structure['m'][$l_Pos];
      $res['sz'] = $g_Structure['s'][$l_Pos];
      $res['sigid'] = $l_SigId;

      $results[] = $res; 
   }

   return $results;
}

///////////////////////////////////////////////////////////////////////////
function printList($par_List, $par_Details = null, $par_NeedIgnore = false, $par_SigId = null, $par_TableName = null) {
  global $g_Structure, $g_NoPrefix, $g_AddPrefix;
  
  $i = 0;

  if ($par_TableName == null) {
     $par_TableName = 'table_' . rand(1000000,9000000);
  }

  $l_Result = '';
  $l_Result .= "<div class=\"flist\"><table cellspacing=1 cellpadding=4 border=0 id=\"" . $par_TableName . "\">";

  $l_Result .= "<thead><tr class=\"tbgh" . ( $i % 2 ). "\">";
  $l_Result .= "<th width=70%>" . AI_STR_004 . "</th>";
  $l_Result .= "<th>" . AI_STR_005 . "</th>";
  $l_Result .= "<th>" . AI_STR_006 . "</th>";
  $l_Result .= "<th width=90>" . AI_STR_007 . "</th>";
  $l_Result .= "<th width=0 class=\"hidd\">CRC32</th>";
  $l_Result .= "<th width=0 class=\"hidd\"></th>";
  $l_Result .= "<th width=0 class=\"hidd\"></th>";
  $l_Result .= "<th width=0 class=\"hidd\"></th>";
  
  $l_Result .= "</tr></thead><tbody>";

  for ($i = 0; $i < count($par_List); $i++) {
    if ($par_SigId != null) {
       $l_SigId = 'id_' . $par_SigId[$i];
    } else {
       $l_SigId = 'id_z' . rand(1000000,9000000);
    }
    
    $l_Pos = $par_List[$i];
        if ($par_NeedIgnore) {
         	if (needIgnore($g_Structure['n'][$par_List[$i]], $g_Structure['crc'][$l_Pos])) {
         		continue;
         	}
        }
  
     $l_Creat = $g_Structure['c'][$l_Pos] > 0 ? date("d/m/Y H:i:s", $g_Structure['c'][$l_Pos]) : '-';
     $l_Modif = $g_Structure['m'][$l_Pos] > 0 ? date("d/m/Y H:i:s", $g_Structure['m'][$l_Pos]) : '-';
     $l_Size = $g_Structure['s'][$l_Pos] > 0 ? bytes2Human($g_Structure['s'][$l_Pos]) : '-';

     if ($par_Details != null) {
        $l_WithMarker = preg_replace('|__AI_MARKER__|smi', '<span class="marker">&nbsp;</span>', $par_Details[$i]);
        $l_WithMarker = preg_replace('|__AI_LINE1__|smi', '<span class="line_no">', $l_WithMarker);
        $l_WithMarker = preg_replace('|__AI_LINE2__|smi', '</span>', $l_WithMarker);
		
        $l_Body = '<div class="details">';

        if ($par_SigId != null) {
           $l_Body .= '<a href="#" onclick="return hsig(\'' . $l_SigId . '\')">[x]</a> ';
        }

        $l_Body .= $l_WithMarker . '</div>';
     } else {
        $l_Body = '';
     }

     $l_Result .= '<tr class="tbg' . ( $i % 2 ). '" o="' . $l_SigId .'">';
	 
	 if (is_file($g_Structure['n'][$l_Pos])) {
//		$l_Result .= '<td><div class="it"><a class="it" target="_blank" href="'. $defaults['site_url'] . 'ai-bolit.php?fn=' .
//	              $g_Structure['n'][$l_Pos] . '&ph=' . realCRC(PASS) . '&c=' . $g_Structure['crc'][$l_Pos] . '">' . $g_Structure['n'][$l_Pos] . '</a></div>' . $l_Body . '</td>';
		$l_Result .= '<td><div class="it"><a class="it">' . makeSafeFn($g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$l_Pos])) . '</a></div>' . $l_Body . '</td>';
	 } else {
		$l_Result .= '<td><div class="it"><a class="it">' . makeSafeFn($g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$par_List[$i]])) . '</a></div></td>';
	 }
	 
     $l_Result .= '<td align=center><div class="ctd">' . $l_Creat . '</div></td>';
     $l_Result .= '<td align=center><div class="ctd">' . $l_Modif . '</div></td>';
     $l_Result .= '<td align=center><div class="ctd">' . $l_Size . '</div></td>';
     $l_Result .= '<td class="hidd"><div class="hidd">' . $g_Structure['crc'][$l_Pos] . '</div></td>';
     $l_Result .= '<td class="hidd"><div class="hidd">' . 'x' . '</div></td>';
     $l_Result .= '<td class="hidd"><div class="hidd">' . $g_Structure['m'][$l_Pos] . '</div></td>';
     $l_Result .= '<td class="hidd"><div class="hidd">' . $l_SigId . '</div></td>';
     $l_Result .= '</tr>';

  }

  $l_Result .= "</tbody></table></div><div class=clear style=\"margin: 20px 0 0 0\"></div>";

  return $l_Result;
}

///////////////////////////////////////////////////////////////////////////
function printPlainList($par_List, $par_Details = null, $par_NeedIgnore = false, $par_SigId = null, $par_TableName = null) {
  global $g_Structure, $g_NoPrefix, $g_AddPrefix;
  
  $l_Result = "";

  $l_Src = array('&quot;', '&lt;', '&gt;', '&amp;', '&#039;');
  $l_Dst = array('"',      '<',    '>',    '&', '\'');

  for ($i = 0; $i < count($par_List); $i++) {
    $l_Pos = $par_List[$i];
        if ($par_NeedIgnore) {
         	if (needIgnore($g_Structure['n'][$par_List[$i]], $g_Structure['crc'][$l_Pos])) {
         		continue;
         	}                      
        }
  

     if ($par_Details != null) {

        $l_Body = preg_replace('|(L\d+).+__AI_MARKER__|smi', '$1: ...', $par_Details[$i]);
        $l_Body = preg_replace('/[^\x20-\x7F]/', '.', $l_Body);
        $l_Body = str_replace($l_Src, $l_Dst, $l_Body);

     } else {
        $l_Body = '';
     }

	 if (is_file($g_Structure['n'][$l_Pos])) {		 
		$l_Result .= $g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$l_Pos]) . "\t\t\t" . $l_Body . "\n";
	 } else {
		$l_Result .= $g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$par_List[$i]]) . "\n";
	 }
	 
  }

  return $l_Result;
}

///////////////////////////////////////////////////////////////////////////
function extractValue(&$par_Str, $par_Name) {
  if (preg_match('|<tr><td class="e">\s*'.$par_Name.'\s*</td><td class="v">(.+?)</td>|sm', $par_Str, $l_Result)) {
     return str_replace('no value', '', strip_tags($l_Result[1]));
  }
}

///////////////////////////////////////////////////////////////////////////
function QCR_ExtractInfo($par_Str) {
   $l_PhpInfoSystem = extractValue($par_Str, 'System');
   $l_PhpPHPAPI = extractValue($par_Str, 'Server API');
   $l_AllowUrlFOpen = extractValue($par_Str, 'allow_url_fopen');
   $l_AllowUrlInclude = extractValue($par_Str, 'allow_url_include');
   $l_DisabledFunction = extractValue($par_Str, 'disable_functions');
   $l_DisplayErrors = extractValue($par_Str, 'display_errors');
   $l_ErrorReporting = extractValue($par_Str, 'error_reporting');
   $l_ExposePHP = extractValue($par_Str, 'expose_php');
   $l_LogErrors = extractValue($par_Str, 'log_errors');
   $l_MQGPC = extractValue($par_Str, 'magic_quotes_gpc');
   $l_MQRT = extractValue($par_Str, 'magic_quotes_runtime');
   $l_OpenBaseDir = extractValue($par_Str, 'open_basedir');
   $l_RegisterGlobals = extractValue($par_Str, 'register_globals');
   $l_SafeMode = extractValue($par_Str, 'safe_mode');


   $l_DisabledFunction = ($l_DisabledFunction == '' ? '-?-' : $l_DisabledFunction);
   $l_OpenBaseDir = ($l_OpenBaseDir == '' ? '-?-' : $l_OpenBaseDir);

   $l_Result = '<div class="title">' . AI_STR_008 . ': ' . phpversion() . '</div>';
   $l_Result .= 'System Version: <span class="php_ok">' . $l_PhpInfoSystem . '</span><br/>';
   $l_Result .= 'PHP API: <span class="php_ok">' . $l_PhpPHPAPI. '</span><br/>';
   $l_Result .= 'allow_url_fopen: <span class="php_' . ($l_AllowUrlFOpen == 'On' ? 'bad' : 'ok') . '">' . $l_AllowUrlFOpen. '</span><br/>';
   $l_Result .= 'allow_url_include: <span class="php_' . ($l_AllowUrlInclude == 'On' ? 'bad' : 'ok') . '">' . $l_AllowUrlInclude. '</span><br/>';
   $l_Result .= 'disable_functions: <span class="php_' . ($l_DisabledFunction == '-?-' ? 'bad' : 'ok') . '">' . $l_DisabledFunction. '</span><br/>';
   $l_Result .= 'display_errors: <span class="php_' . ($l_DisplayErrors == 'On' ? 'ok' : 'bad') . '">' . $l_DisplayErrors. '</span><br/>';
   $l_Result .= 'error_reporting: <span class="php_ok">' . $l_ErrorReporting. '</span><br/>';
   $l_Result .= 'expose_php: <span class="php_' . ($l_ExposePHP == 'On' ? 'bad' : 'ok') . '">' . $l_ExposePHP. '</span><br/>';
   $l_Result .= 'log_errors: <span class="php_' . ($l_LogErrors == 'On' ? 'ok' : 'bad') . '">' . $l_LogErrors . '</span><br/>';
   $l_Result .= 'magic_quotes_gpc: <span class="php_' . ($l_MQGPC == 'On' ? 'ok' : 'bad') . '">' . $l_MQGPC. '</span><br/>';
   $l_Result .= 'magic_quotes_runtime: <span class="php_' . ($l_MQRT == 'On' ? 'bad' : 'ok') . '">' . $l_MQRT. '</span><br/>';
   $l_Result .= 'register_globals: <span class="php_' . ($l_RegisterGlobals == 'On' ? 'bad' : 'ok') . '">' . $l_RegisterGlobals . '</span><br/>';
   $l_Result .= 'open_basedir: <span class="php_' . ($l_OpenBaseDir == '-?-' ? 'bad' : 'ok') . '">' . $l_OpenBaseDir . '</span><br/>';
   
   if (phpversion() < '5.3.0') {
      $l_Result .= 'safe_mode (PHP < 5.3.0): <span class="php_' . ($l_SafeMode == 'On' ? 'ok' : 'bad') . '">' . $l_SafeMode. '</span><br/>';
   }

   return $l_Result . '<p>';
}

///////////////////////////////////////////////////////////////////////////
   function addSlash($dir) {
      return rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
   }

///////////////////////////////////////////////////////////////////////////
function QCR_Debug($par_Str = "") {
  if (!DEBUG_MODE) {
     return;
  }

  $l_MemInfo = ' ';  
  if (function_exists('memory_get_usage')) {
     $l_MemInfo .= ' curmem=' .  bytes2Human(memory_get_usage());
  }

  if (function_exists('memory_get_peak_usage')) {
     $l_MemInfo .= ' maxmem=' .  bytes2Human(memory_get_peak_usage());
  }

  stdOut("\n" . date('H:i:s') . ': ' . $par_Str . $l_MemInfo . "\n");
}


///////////////////////////////////////////////////////////////////////////
function QCR_ScanDirectories($l_RootDir)
{
	global $g_Structure, $g_Counter, $g_Doorway, $g_FoundTotalFiles, $g_FoundTotalDirs, 
			$defaults, $g_SkippedFolders, $g_UrlIgnoreList, $g_DirIgnoreList, $g_UnsafeDirArray, 
                        $g_UnsafeFilesFound, $g_SymLinks, $g_HiddenFiles, $g_UnixExec, $g_IgnoredExt, $g_SensitiveFiles, 
						$g_SuspiciousFiles, $g_ShortListExt, $l_SkipSample;

	static $l_Buffer = '';

	$l_DirCounter = 0;
	$l_DoorwayFilesCounter = 0;
	$l_SourceDirIndex = $g_Counter - 1;

        $l_SkipSample = array();

	QCR_Debug('Scan ' . $l_RootDir);

        $l_QuotedSeparator = quotemeta(DIR_SEPARATOR); 
 	if ($l_DIRH = @opendir($l_RootDir))
	{
		while (($l_FileName = readdir($l_DIRH)) !== false)
		{
			if ($l_FileName == '.' || $l_FileName == '..') continue;

			$l_FileName = $l_RootDir . DIR_SEPARATOR . $l_FileName;

			$l_Type = filetype($l_FileName);
            if ($l_Type == "link") 
            {
                $g_SymLinks[] = $l_FileName;
                continue;
            } else			
			if ($l_Type != "file" && $l_Type != "dir" ) {
			        if (!in_array($l_FileName, $g_UnixExec)) {
				   $g_UnixExec[] = $l_FileName;
				}

				continue;
			}	
						
			$l_Ext = strtolower(pathinfo($l_FileName, PATHINFO_EXTENSION));
			$l_IsDir = is_dir($l_FileName);

			if (in_array($l_Ext, $g_SuspiciousFiles)) 
			{
			        if (!in_array($l_FileName, $g_UnixExec)) {
                		   $g_UnixExec[] = $l_FileName;
                                } 
            		}

			// which files should be scanned
			$l_NeedToScan = SCAN_ALL_FILES || (in_array($l_Ext, $g_SensitiveFiles));

			if (in_array(strtolower($l_Ext), $g_IgnoredExt)) {    
		           $l_NeedToScan = false;
                        }

      			// if folder in ignore list
      			$l_Skip = false;
      			for ($dr = 0; $dr < count($g_DirIgnoreList); $dr++) {
      				if (($g_DirIgnoreList[$dr] != '') &&
      				   preg_match('#' . $g_DirIgnoreList[$dr] . '#', $l_FileName, $l_Found)) {
      				   if (!in_array($g_DirIgnoreList[$dr], $l_SkipSample)) {
                                      $l_SkipSample[] = $g_DirIgnoreList[$dr];
                                   } else {
        		             $l_Skip = true;
                                     $l_NeedToScan = false;
                                   }
      				}
      			}


			if ($l_IsDir)
			{
				// skip on ignore
				if ($l_Skip) {
				   $g_SkippedFolders[] = $l_FileName;
				   continue;
				}
				
				$l_BaseName = basename($l_FileName);

				if ((strpos($l_BaseName, '.') === 0) && ($l_BaseName != '.htaccess')) {
	               $g_HiddenFiles[] = $l_FileName;
	            }

//				$g_Structure['d'][$g_Counter] = $l_IsDir;
//				$g_Structure['n'][$g_Counter] = $l_FileName;
				if (ONE_PASS) {
					$g_Structure['n'][$g_Counter] = $l_FileName . DIR_SEPARATOR;
				} else {
					$l_Buffer .= $l_FileName . DIR_SEPARATOR . "\n";
				}

				$l_DirCounter++;

				if ($l_DirCounter > MAX_ALLOWED_PHP_HTML_IN_DIR)
				{
					$g_Doorway[] = $l_SourceDirIndex;
					$l_DirCounter = -655360;
				}

				$g_Counter++;
				$g_FoundTotalDirs++;

				QCR_ScanDirectories($l_FileName);
			} else
			{
				if ($l_NeedToScan)
				{
					$g_FoundTotalFiles++;
					if (in_array($l_Ext, $g_ShortListExt)) 
					{
						$l_DoorwayFilesCounter++;
						
						if ($l_DoorwayFilesCounter > MAX_ALLOWED_PHP_HTML_IN_DIR)
						{
							$g_Doorway[] = $l_SourceDirIndex;
							$l_DoorwayFilesCounter = -655360;
						}
					}

					if (ONE_PASS) {
						QCR_ScanFile($l_FileName, $g_Counter++);
					} else {
						$l_Buffer .= $l_FileName."\n";
					}

					$g_Counter++;
				}
			}

			if (strlen($l_Buffer) > 32000)
			{ 
				file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file ".QUEUE_FILENAME);
				$l_Buffer = '';
			}

		}

		closedir($l_DIRH);
	}
	
	if (($l_RootDir == ROOT_PATH) && !empty($l_Buffer)) {
		file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
		$l_Buffer = '';                                                                            
	}

}


///////////////////////////////////////////////////////////////////////////
function getFragment($par_Content, $par_Pos) {
  $l_MaxChars = MAX_PREVIEW_LEN;
  $l_MaxLen = strlen($par_Content);
  $l_RightPos = min($par_Pos + $l_MaxChars, $l_MaxLen); 
  $l_MinPos = max(0, $par_Pos - $l_MaxChars);

  $l_FoundStart = substr($par_Content, 0, $par_Pos);
  $l_FoundStart = str_replace("\r", '', $l_FoundStart);
  $l_LineNo = strlen($l_FoundStart) - strlen(str_replace("\n", '', $l_FoundStart)) + 1;

  $par_Content = preg_replace('/[\x00-\x1F\x80-\xFF]/', '~', $par_Content);
  $par_Content = preg_replace('~[ \t]+~', ' ', $par_Content);

  $l_Res = '__AI_LINE1__' . $l_LineNo . "__AI_LINE2__  " . ($l_MinPos > 0 ? '…' : '') . substr($par_Content, $l_MinPos, $par_Pos - $l_MinPos) . 
           '__AI_MARKER__' . substr($par_Content, $par_Pos, $l_RightPos - $par_Pos - 1);

  $l_Res = makeSafeFn(UnwrapObfu($l_Res));
  $l_Res = str_replace('~', '·', $l_Res);
  $l_Res = preg_replace('/\s+/smi', ' ', $l_Res);
  $l_Res = str_replace('' . '?php', '' . '?php ', $l_Res);

  return $l_Res;
}

///////////////////////////////////////////////////////////////////////////
function escapedHexToHex($escaped)
{ $GLOBALS['g_EncObfu']++; return chr(hexdec($escaped[1])); }
function escapedOctDec($escaped)
{ $GLOBALS['g_EncObfu']++; return chr(octdec($escaped[1])); }
function escapedDec($escaped)
{ $GLOBALS['g_EncObfu']++; return chr($escaped[1]); }

///////////////////////////////////////////////////////////////////////////
if (!defined('T_ML_COMMENT')) {
   define('T_ML_COMMENT', T_COMMENT);
} else {
   define('T_DOC_COMMENT', T_ML_COMMENT);
}
          	
function UnwrapObfu($par_Content) {
  $GLOBALS['g_EncObfu'] = 0;
  
  $search  = array( ' ;', ' =', ' ,', ' .', ' (', ' )', ' {', ' }', '; ', '= ', ', ', '. ', '( ', '( ', '{ ', '} ', ' !', ' >', ' <', ' _', '_ ', '< ',  '> ', ' $', ' %',   '% ', '# ', ' #', '^ ', ' ^', ' &', '& ', ' ?', '? ');
  $replace = array(  ';',  '=',  ',',  '.',  '(',  ')',  '{',  '}', ';',  '=',  ',',  '.',  '(',   ')', '{',  '}',   '!',  '>',  '<',  '_', '_',  '<',   '>',   '$',  '%',   '%',  '#',   '#', '^',   '^',  '&', '&',   '?', '?');
  $par_Content = str_replace('@', '', $par_Content);
  $par_Content = preg_replace('~\s+~smi', ' ', $par_Content);
  $par_Content = str_replace($search, $replace, $par_Content);
  $par_Content = preg_replace_callback('~\bchr\(\s*([0-9a-fA-FxX]+)\s*\)~', function ($m) { return "'".chr(intval($m[1], 0))."'"; }, $par_Content );

  $par_Content = preg_replace_callback('/\\\\x([a-fA-F0-9]{1,2})/i','escapedHexToHex', $par_Content);
  $par_Content = preg_replace_callback('/\\\\([0-9]{1,3})/i','escapedOctDec', $par_Content);

  $par_Content = preg_replace('/[\'"]\s*?\.+\s*?[\'"]/smi', '', $par_Content);
  $par_Content = preg_replace('/[\'"]\s*?\++\s*?[\'"]/smi', '', $par_Content);

  $content = str_replace('<?$', '<?php$', $content);
  $content = str_replace('<?php', '<?php ', $content);

  return $par_Content;
}

///////////////////////////////////////////////////////////////////////////
// Unicode BOM is U+FEFF, but after encoded, it will look like this.
define ('UTF32_BIG_ENDIAN_BOM'   , chr(0x00) . chr(0x00) . chr(0xFE) . chr(0xFF));
define ('UTF32_LITTLE_ENDIAN_BOM', chr(0xFF) . chr(0xFE) . chr(0x00) . chr(0x00));
define ('UTF16_BIG_ENDIAN_BOM'   , chr(0xFE) . chr(0xFF));
define ('UTF16_LITTLE_ENDIAN_BOM', chr(0xFF) . chr(0xFE));
define ('UTF8_BOM'               , chr(0xEF) . chr(0xBB) . chr(0xBF));

function detect_utf_encoding($text) {
    $first2 = substr($text, 0, 2);
    $first3 = substr($text, 0, 3);
    $first4 = substr($text, 0, 3);
    
    if ($first3 == UTF8_BOM) return 'UTF-8';
    elseif ($first4 == UTF32_BIG_ENDIAN_BOM) return 'UTF-32BE';
    elseif ($first4 == UTF32_LITTLE_ENDIAN_BOM) return 'UTF-32LE';
    elseif ($first2 == UTF16_BIG_ENDIAN_BOM) return 'UTF-16BE';
    elseif ($first2 == UTF16_LITTLE_ENDIAN_BOM) return 'UTF-16LE';

    return false;
}

///////////////////////////////////////////////////////////////////////////
function QCR_SearchPHP($src)
{
  if (preg_match("/(<\?php[\w\s]{5,})/smi", $src, $l_Found, PREG_OFFSET_CAPTURE)) {
	  return $l_Found[0][1];
  }

  if (preg_match("/(<script[^>]*language\s*=\s*)('|\"|)php('|\"|)([^>]*>)/i", $src, $l_Found, PREG_OFFSET_CAPTURE)) {
    return $l_Found[0][1];
  }

  return false;
}


///////////////////////////////////////////////////////////////////////////
function knowUrl($par_URL) {
  global $g_UrlIgnoreList;

  for ($jk = 0; $jk < count($g_UrlIgnoreList); $jk++) {
     if  (stripos($par_URL, $g_UrlIgnoreList[$jk]) !== false) {
     	return true;
     }
  }

  return false;
}

///////////////////////////////////////////////////////////////////////////

function makeSummary($par_Str, $par_Number, $par_Style) {
   return '<tr><td class="' . $par_Style . '" width=400>' . $par_Str . '</td><td class="' . $par_Style . '">' . $par_Number . '</td></tr>';
}

///////////////////////////////////////////////////////////////////////////

function CheckVulnerability($par_Filename, $par_Index, $par_Content) {
    global $g_Vulnerable, $g_CmsListDetector;
	

	$l_Vuln = array();

        $par_Filename = strtolower($par_Filename);

	if (
	    (strpos($par_Filename, 'libraries/joomla/session/session.php') !== false) &&
		(strpos($par_Content, '&& filter_var($_SERVER[\'HTTP_X_FORWARDED_FOR') === false)
		) 
	{		
			$l_Vuln['id'] = 'RCE : https://docs.joomla.org/Security_hotfixes_for_Joomla_EOL_versions';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
	}

	if (
	    (strpos($par_Filename, 'administrator/components/com_media/helpers/media.php') !== false) &&
		(strpos($par_Content, '$format == \'\' || $format == false ||') === false)
		) 
	{		
		if ($g_CmsListDetector->isCms(CMS_JOOMLA, '1.5')) {
			$l_Vuln['id'] = 'AFU : https://docs.joomla.org/Security_hotfixes_for_Joomla_EOL_versions';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if (
	    (strpos($par_Filename, 'joomla/filesystem/file.php') !== false) &&
		(strpos($par_Content, '$file = rtrim($file, \'.\');') === false)
		) 
	{		
		if ($g_CmsListDetector->isCms(CMS_JOOMLA, '1.5')) {
			$l_Vuln['id'] = 'AFU : https://docs.joomla.org/Security_hotfixes_for_Joomla_EOL_versions';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if ((strpos($par_Filename, 'editor/filemanager/upload/test.html') !== false) ||
		(stripos($par_Filename, 'editor/filemanager/browser/default/connectors/php/') !== false) ||
		(stripos($par_Filename, 'editor/filemanager/connectors/uploadtest.html') !== false) ||
	   (strpos($par_Filename, 'editor/filemanager/browser/default/connectors/test.html') !== false)) {
		$l_Vuln['id'] = 'AFU : FCKEDITOR : http://www.exploit-db.com/exploits/17644/ & /exploit/249';
		$l_Vuln['ndx'] = $par_Index;
		$g_Vulnerable[] = $l_Vuln;
		return true;
	}

	if ((strpos($par_Filename, 'inc_php/image_view.class.php') !== false) ||
	    (strpos($par_Filename, '/inc_php/framework/image_view.class.php') !== false)) {
		if (strpos($par_Content, 'showImageByID') === false) {
			$l_Vuln['id'] = 'AFU : REVSLIDER : http://www.exploit-db.com/exploits/35385/';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if ((strpos($par_Filename, 'elfinder/php/connector.php') !== false) ||
	    (strpos($par_Filename, 'elfinder/elfinder.') !== false)) {
			$l_Vuln['id'] = 'AFU : elFinder';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
	}

	if (strpos($par_Filename, 'includes/database/database.inc') !== false) {
		if (strpos($par_Content, 'foreach ($data as $i => $value)') !== false) {
			$l_Vuln['id'] = 'SQLI : DRUPAL : CVE-2014-3704';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if (strpos($par_Filename, 'engine/classes/min/index.php') !== false) {
		if (strpos($par_Content, 'tr_replace(chr(0)') === false) {
			$l_Vuln['id'] = 'AFD : MINIFY : CVE-2013-6619';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if (( strpos($par_Filename, 'timthumb.php') !== false ) || 
	    ( strpos($par_Filename, 'thumb.php') !== false ) || 
	    ( strpos($par_Filename, 'cache.php') !== false ) || 
	    ( strpos($par_Filename, '_img.php') !== false )) {
		if (strpos($par_Content, 'code.google.com/p/timthumb') !== false && strpos($par_Content, '2.8.14') === false ) {
			$l_Vuln['id'] = 'RCE : TIMTHUMB : CVE-2011-4106,CVE-2014-4663';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if (strpos($par_Filename, 'components/com_rsform/helpers/rsform.php') !== false) {
		if (strpos($par_Content, 'eval($form->ScriptDisplay);') !== false) {
			$l_Vuln['id'] = 'RCE : RSFORM : rsform.php, LINE 1605';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if (strpos($par_Filename, 'fancybox-for-wordpress/fancybox.php') !== false) {
		if (strpos($par_Content, '\'reset\' == $_REQUEST[\'action\']') !== false) {
			$l_Vuln['id'] = 'CODE INJECTION : FANCYBOX';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}


	if (strpos($par_Filename, 'cherry-plugin/admin/import-export/upload.php') !== false) {
		if (strpos($par_Content, 'verify nonce') === false) {
			$l_Vuln['id'] = 'AFU : Cherry Plugin';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}
	
	
	if (strpos($par_Filename, 'tiny_mce/plugins/tinybrowser/tinybrowser.php') !== false) {	
		$l_Vuln['id'] = 'AFU : TINYMCE : http://www.exploit-db.com/exploits/9296/';
		$l_Vuln['ndx'] = $par_Index;
		$g_Vulnerable[] = $l_Vuln;
		
		return true;
	}

	if (strpos($par_Filename, '/bx_1c_import.php') !== false) {	
		if (strpos($par_Content, '$_GET[\'action\']=="getfiles"') !== false) {
   		   $l_Vuln['id'] = 'AFD : https://habrahabr.ru/company/dsec/blog/326166/';
   		   $l_Vuln['ndx'] = $par_Index;
   		   $g_Vulnerable[] = $l_Vuln;
   		
   		   return true;
                }
	}

	if (strpos($par_Filename, 'scripts/setup.php') !== false) {		
		if (strpos($par_Content, 'PMA_Config') !== false) {
			$l_Vuln['id'] = 'CODE INJECTION : PHPMYADMIN : http://1337day.com/exploit/5334';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if (strpos($par_Filename, '/uploadify.php') !== false) {		
		if (strpos($par_Content, 'move_uploaded_file($tempFile,$targetFile') !== false) {
			$l_Vuln['id'] = 'AFU : UPLOADIFY : CVE: 2012-1153';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if (strpos($par_Filename, 'com_adsmanager/controller.php') !== false) {		
		if (strpos($par_Content, 'move_uploaded_file($file[\'tmp_name\'], $tempPath.\'/\'.basename($file[') !== false) {
			$l_Vuln['id'] = 'AFU : https://revisium.com/ru/blog/adsmanager_afu.html';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if (strpos($par_Filename, 'wp-content/plugins/wp-mobile-detector/resize.php') !== false) {		
		if (strpos($par_Content, 'file_put_contents($path, file_get_contents($_REQUEST[\'src\']));') !== false) {
			$l_Vuln['id'] = 'AFU : https://www.pluginvulnerabilities.com/2016/05/31/aribitrary-file-upload-vulnerability-in-wp-mobile-detector/';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}


	if (strpos($par_Filename, 'core/lib/drupal.php') !== false) {		
                $version = '';
                if (preg_match('|VERSION\s*=\s*\'(8\.\d+\.\d+)\'|smi', $par_Content, $tmp_ver)) {
                   $version = $tmp_ver[1];
                }

		if (($version !== '') && (version_compare($version, '8.5.1', '<'))) {
			$l_Vuln['id'] = 'Drupageddon 2 : SA-CORE-2018–002';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		

		return false;
	}

	if (strpos($par_Filename, 'changelog.txt') !== false) {		
                $version = '';
                if (preg_match('|Drupal\s+(7\.\d+),|smi', $par_Content, $tmp_ver)) {
                   $version = $tmp_ver[1];
                }

		if (($version !== '') && (version_compare($version, '7.58', '<'))) {
			$l_Vuln['id'] = 'Drupageddon 2 : SA-CORE-2018–002';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if (strpos($par_Filename, 'phpmailer.php') !== false) {		
		if (strpos($par_Content, 'PHPMailer') !== false) {
                        $l_Found = preg_match('~Version:\s*(\d+)\.(\d+)\.(\d+)~', $par_Content, $l_Match);

                        if ($l_Found) {
                           $l_Version = $l_Match[1] * 1000 + $l_Match[2] * 100 + $l_Match[3];

                           if ($l_Version < 2520) {
                              $l_Found = false;
                           }
                        }

                        if (!$l_Found) {

                           $l_Found = preg_match('~Version\s*=\s*\'(\d+)\.*(\d+)\.(\d+)~', $par_Content, $l_Match);
                           if ($l_Found) {
                              $l_Version = $l_Match[1] * 1000 + $l_Match[2] * 100 + $l_Match[3];
                              if ($l_Version < 5220) {
                                 $l_Found = false;
                              }
                           }
			}


		        if (!$l_Found) {
	   		   $l_Vuln['id'] = 'RCE : CVE-2016-10045, CVE-2016-10031';
			   $l_Vuln['ndx'] = $par_Index;
			   $g_Vulnerable[] = $l_Vuln;
			   return true;
                        }
		}
		
		return false;
	}




}

///////////////////////////////////////////////////////////////////////////
function QCR_GoScan($par_Offset)
{
	global $g_IframerFragment, $g_Iframer, $g_Redirect, $g_Doorway, $g_EmptyLink, $g_Structure, $g_Counter, 
		   $g_HeuristicType, $g_HeuristicDetected, $g_TotalFolder, $g_TotalFiles, $g_WarningPHP, $g_AdwareList,
		   $g_CriticalPHP, $g_Phishing, $g_CriticalJS, $g_UrlIgnoreList, $g_CriticalJSFragment, $g_PHPCodeInside, $g_PHPCodeInsideFragment, 
		   $g_NotRead, $g_WarningPHPFragment, $g_WarningPHPSig, $g_BigFiles, $g_RedirectPHPFragment, $g_EmptyLinkSrc, $g_CriticalPHPSig, $g_CriticalPHPFragment, 
           $g_Base64Fragment, $g_UnixExec, $g_PhishingSigFragment, $g_PhishingFragment, $g_PhishingSig, $g_CriticalJSSig, $g_IframerFragment, $g_CMS, $defaults, $g_AdwareListFragment, $g_KnownList,$g_Vulnerable;

    QCR_Debug('QCR_GoScan ' . $par_Offset);

	$i = 0;
	
	try {
		$s_file = new SplFileObject(QUEUE_FILENAME);
		$s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);

		foreach ($s_file as $l_Filename) {
			QCR_ScanFile($l_Filename, $i++);
		}
		
		unset($s_file);	
	}
	catch (Exception $e) { QCR_Debug( $e->getMessage() ); }
}

///////////////////////////////////////////////////////////////////////////
function QCR_ScanFile($l_Filename, $i = 0)
{
	global $g_IframerFragment, $g_Iframer, $g_Redirect, $g_Doorway, $g_EmptyLink, $g_Structure, $g_Counter, 
		   $g_HeuristicType, $g_HeuristicDetected, $g_TotalFolder, $g_TotalFiles, $g_WarningPHP, $g_AdwareList,
		   $g_CriticalPHP, $g_Phishing, $g_CriticalJS, $g_UrlIgnoreList, $g_CriticalJSFragment, $g_PHPCodeInside, $g_PHPCodeInsideFragment, 
		   $g_NotRead, $g_WarningPHPFragment, $g_WarningPHPSig, $g_BigFiles, $g_RedirectPHPFragment, $g_EmptyLinkSrc, $g_CriticalPHPSig, $g_CriticalPHPFragment, 
           $g_Base64Fragment, $g_UnixExec, $g_PhishingSigFragment, $g_PhishingFragment, $g_PhishingSig, $g_CriticalJSSig, $g_IframerFragment, $g_CMS, $defaults, $g_AdwareListFragment, 
           $g_KnownList,$g_Vulnerable, $g_CriticalFiles, $g_DeMapper;

	global $g_CRC;
	static $_files_and_ignored = 0;

			$l_CriticalDetected = false;
			$l_Stat = stat($l_Filename);

			if (substr($l_Filename, -1) == DIR_SEPARATOR) {
				// FOLDER
				$g_Structure['n'][$i] = $l_Filename;
				$g_TotalFolder++;
				printProgress($_files_and_ignored, $l_Filename);
				return;
			}

			QCR_Debug('Scan file ' . $l_Filename);
			printProgress(++$_files_and_ignored, $l_Filename);

     			// ignore itself
     			if ($l_Filename == __FILE__) {
     				return;
     			}

			// FILE
			if ((MAX_SIZE_TO_SCAN > 0 AND $l_Stat['size'] > MAX_SIZE_TO_SCAN) || ($l_Stat['size'] < 0))
			{
				$g_BigFiles[] = $i;

                                if (function_exists('aibolit_onBigFile')) { aibolit_onBigFile($l_Filename); }

				AddResult($l_Filename, $i);

		                $l_Ext = strtolower(pathinfo($l_Filename, PATHINFO_EXTENSION));
                                if ((!AI_HOSTER) && in_array($l_Ext, $g_CriticalFiles)) {
				    $g_CriticalPHP[] = $i;
				    $g_CriticalPHPFragment[] = "BIG FILE. SKIPPED.";
				    $g_CriticalPHPSig[] = "big_1";
                                }
			}
			else
			{
				$g_TotalFiles++;

			$l_TSStartScan = microtime(true);

		$l_Ext = strtolower(pathinfo($l_Filename, PATHINFO_EXTENSION));
		if (filetype($l_Filename) == 'file') {
                   $l_Content = @file_get_contents($l_Filename);
		   if (SHORT_PHP_TAG) {
//                      $l_Content = preg_replace('|<\?\s|smiS', '<?php ', $l_Content); 
                   }

                   $l_Unwrapped = @php_strip_whitespace($l_Filename);
                }

		
                if ((($l_Content == '') || ($l_Unwrapped == '')) && ($l_Stat['size'] > 0)) {
                   $g_NotRead[] = $i;
                   if (function_exists('aibolit_onReadError')) { aibolit_onReadError($l_Filename, 'io'); }
                   AddResult('[io] ' . $l_Filename, $i);
                   return;
                }

				// unix executables
				if (strpos($l_Content, chr(127) . 'ELF') !== false) 
				{
			        	if (!in_array($l_Filename, $g_UnixExec)) {
                    				$g_UnixExec[] = $l_Filename;
					}

				        return;
                		}

				$g_CRC = _hash_($l_Unwrapped);

				$l_UnicodeContent = detect_utf_encoding($l_Content);
				//$l_Unwrapped = $l_Content;

				// check vulnerability in files
				$l_CriticalDetected = CheckVulnerability($l_Filename, $i, $l_Content);				

				if ($l_UnicodeContent !== false) {
       				   if (function_exists('iconv')) {
				      $l_Unwrapped = iconv($l_UnicodeContent, "CP1251//IGNORE", $l_Unwrapped);
//       			   if (function_exists('mb_convert_encoding')) {
//                                    $l_Unwrapped = mb_convert_encoding($l_Unwrapped, $l_UnicodeContent, "CP1251");
                                   } else {
                                      $g_NotRead[] = $i;
                                      if (function_exists('aibolit_onReadError')) { aibolit_onReadError($l_Filename, 'ec'); }
                                      AddResult('[ec] ' . $l_Filename, $i);
				   }
                                }

				// critical
				$g_SkipNextCheck = false;

                                $l_DeobfType = '';
				if ((!AI_HOSTER) || AI_DEOBFUSCATE) {
                                   $l_DeobfType = getObfuscateType($l_Unwrapped);
                                }

                                if ($l_DeobfType != '') {
                                   $l_Unwrapped = deobfuscate($l_Unwrapped);
				   $g_SkipNextCheck = checkFalsePositives($l_Filename, $l_Unwrapped, $l_DeobfType);
                                } else {
     				   if (DEBUG_MODE) {
				      stdOut("\n...... NOT OBFUSCATED\n");
				   }
				}

				$l_Unwrapped = UnwrapObfu($l_Unwrapped);
				
				if ((!$g_SkipNextCheck) && CriticalPHP($l_Filename, $i, $l_Unwrapped, $l_Pos, $l_SigId))
				{
				        if ($l_Ext == 'js') {
 					   $g_CriticalJS[] = $i;
 					   $g_CriticalJSFragment[] = getFragment($l_Unwrapped, $l_Pos);
 					   $g_CriticalJSSig[] = $l_SigId;
                                        } else {
       					   $g_CriticalPHP[] = $i;
       					   $g_CriticalPHPFragment[] = getFragment($l_Unwrapped, $l_Pos);
      					   $g_CriticalPHPSig[] = $l_SigId;
                                        }

					$g_SkipNextCheck = true;
				} else {
         				if ((!$g_SkipNextCheck) && CriticalPHP($l_Filename, $i, $l_Content, $l_Pos, $l_SigId))
         				{
					        if ($l_Ext == 'js') {
         					   $g_CriticalJS[] = $i;
         					   $g_CriticalJSFragment[] = getFragment($l_Content, $l_Pos);
         					   $g_CriticalJSSig[] = $l_SigId;
                                                } else {
               					   $g_CriticalPHP[] = $i;
               					   $g_CriticalPHPFragment[] = getFragment($l_Content, $l_Pos);
      						   $g_CriticalPHPSig[] = $l_SigId;
                                                }

         					$g_SkipNextCheck = true;
         				}
				}

				$l_TypeDe = 0;
			    if ((!$g_SkipNextCheck) && HeuristicChecker($l_Content, $l_TypeDe, $l_Filename)) {
					$g_HeuristicDetected[] = $i;
					$g_HeuristicType[] = $l_TypeDe;
					$l_CriticalDetected = true;
				}

				// critical JS
				if (!$g_SkipNextCheck) {
					$l_Pos = CriticalJS($l_Filename, $i, $l_Unwrapped, $l_SigId);
					if ($l_Pos !== false)
					{
					        if ($l_Ext == 'js') {
         					   $g_CriticalJS[] = $i;
         					   $g_CriticalJSFragment[] = getFragment($l_Unwrapped, $l_Pos);
         					   $g_CriticalJSSig[] = $l_SigId;
                                                } else {
               					   $g_CriticalPHP[] = $i;
               					   $g_CriticalPHPFragment[] = getFragment($l_Unwrapped, $l_Pos);
      						   $g_CriticalPHPSig[] = $l_SigId;
                                                }

						$g_SkipNextCheck = true;
					}
			    }

				// phishing
				if (!$g_SkipNextCheck) {
					$l_Pos = Phishing($l_Filename, $i, $l_Unwrapped, $l_SigId);
					if ($l_Pos === false) {
                                            $l_Pos = Phishing($l_Filename, $i, $l_Content, $l_SigId);
                                        }

					if ($l_Pos !== false)
					{
						$g_Phishing[] = $i;
						$g_PhishingFragment[] = getFragment($l_Unwrapped, $l_Pos);
						$g_PhishingSigFragment[] = $l_SigId;
						$g_SkipNextCheck = true;
					}
				}

			
			if (!$g_SkipNextCheck) {
				if (SCAN_ALL_FILES || stripos($l_Filename, 'index.'))
				{
					// check iframes
					if (preg_match_all('|<iframe[^>]+src.+?>|smi', $l_Unwrapped, $l_Found, PREG_SET_ORDER)) 
					{
						for ($kk = 0; $kk < count($l_Found); $kk++) {
						    $l_Pos = stripos($l_Found[$kk][0], 'http://');
						    $l_Pos = $l_Pos || stripos($l_Found[$kk][0], 'https://');
						    $l_Pos = $l_Pos || stripos($l_Found[$kk][0], 'ftp://');
							if  (($l_Pos !== false ) && (!knowUrl($l_Found[$kk][0]))) {
         						$g_Iframer[] = $i;
         						$g_IframerFragment[] = getFragment($l_Found[$kk][0], $l_Pos);
         						$l_CriticalDetected = true;
							}
						}
					}

					// check empty links
					if ((($defaults['report_mask'] & REPORT_MASK_SPAMLINKS) == REPORT_MASK_SPAMLINKS) &&
					   (preg_match_all('|<a[^>]+href([^>]+?)>(.*?)</a>|smi', $l_Unwrapped, $l_Found, PREG_SET_ORDER)))
					{
						for ($kk = 0; $kk < count($l_Found); $kk++) {
							if  ((stripos($l_Found[$kk][1], 'http://') !== false) &&
                                                            (trim(strip_tags($l_Found[$kk][2])) == '')) {

								$l_NeedToAdd = true;

							    if  ((stripos($l_Found[$kk][1], $defaults['site_url']) !== false)
                                                                 || knowUrl($l_Found[$kk][1])) {
										$l_NeedToAdd = false;
								}
								
								if ($l_NeedToAdd && (count($g_EmptyLink) < MAX_EXT_LINKS)) {
									$g_EmptyLink[] = $i;
									$g_EmptyLinkSrc[$i][] = substr($l_Found[$kk][0], 0, MAX_PREVIEW_LEN);
									$l_CriticalDetected = true;
								}
							}
						}
					}
				}

				// check for PHP code inside any type of file
				if (stripos($l_Ext, 'ph') === false)
				{
					$l_Pos = QCR_SearchPHP($l_Content);
					if ($l_Pos !== false)
					{
						$g_PHPCodeInside[] = $i;
						$g_PHPCodeInsideFragment[] = getFragment($l_Unwrapped, $l_Pos);
						$l_CriticalDetected = true;
					}
				}

				// htaccess
				if (stripos($l_Filename, '.htaccess'))
				{
				
					if (stripos($l_Content, 'index.php?name=$1') !== false ||
						stripos($l_Content, 'index.php?m=1') !== false
					)
					{
						$g_SuspDir[] = $i;
					}

					$l_HTAContent = preg_replace('|^\s*#.+$|m', '', $l_Content);

					$l_Pos = stripos($l_Content, 'auto_prepend_file');
					if ($l_Pos !== false) {
						$g_Redirect[] = $i;
						$g_RedirectPHPFragment[] = getFragment($l_Content, $l_Pos);
						$l_CriticalDetected = true;
					}
					
					$l_Pos = stripos($l_Content, 'auto_append_file');
					if ($l_Pos !== false) {
						$g_Redirect[] = $i;
						$g_RedirectPHPFragment[] = getFragment($l_Content, $l_Pos);
						$l_CriticalDetected = true;
					}

					$l_Pos = stripos($l_Content, '^(%2d|-)[^=]+$');
					if ($l_Pos !== false)
					{
						$g_Redirect[] = $i;
                        			$g_RedirectPHPFragment[] = getFragment($l_Content, $l_Pos);
						$l_CriticalDetected = true;
					}

					if (!$l_CriticalDetected) {
						$l_Pos = stripos($l_Content, '%{HTTP_USER_AGENT}');
						if ($l_Pos !== false)
						{
							$g_Redirect[] = $i;
							$g_RedirectPHPFragment[] = getFragment($l_Content, $l_Pos);
							$l_CriticalDetected = true;
						}
					}

					if (!$l_CriticalDetected) {
						if (
							preg_match_all("|RewriteRule\s+.+?\s+http://(.+?)/.+\s+\[.*R=\d+.*\]|smi", $l_HTAContent, $l_Found, PREG_SET_ORDER)
						)
						{
							$l_Host = str_replace('www.', '', $_SERVER['HTTP_HOST']);
							for ($j = 0; $j < sizeof($l_Found); $j++)
							{
								$l_Found[$j][1] = str_replace('www.', '', $l_Found[$j][1]);
								if ($l_Found[$j][1] != $l_Host)
								{
									$g_Redirect[] = $i;
									$l_CriticalDetected = true;
									break;
								}
							}
						}
					}

					unset($l_HTAContent);
			    }
			

			    // warnings
				$l_Pos = '';
				
			    if (WarningPHP($l_Filename, $l_Unwrapped, $l_Pos, $l_SigId))
				{       
					$l_Prio = 1;
					if (strpos($l_Filename, '.ph') !== false) {
					   $l_Prio = 0;
					}
					
					$g_WarningPHP[$l_Prio][] = $i;
					$g_WarningPHPFragment[$l_Prio][] = getFragment($l_Unwrapped, $l_Pos);
					$g_WarningPHPSig[] = $l_SigId;

					$l_CriticalDetected = true;
				}
				

				// adware
				if (Adware($l_Filename, $l_Unwrapped, $l_Pos))
				{
					$g_AdwareList[] = $i;
					$g_AdwareListFragment[] = getFragment($l_Unwrapped, $l_Pos);
					$l_CriticalDetected = true;
				}

				// articles
				if (stripos($l_Filename, 'article_index'))
				{
					$g_AdwareList[] = $i;
					$l_CriticalDetected = true;
				}
			}
		} // end of if (!$g_SkipNextCheck) {
			
			unset($l_Unwrapped);
			unset($l_Content);
			
			//printProgress(++$_files_and_ignored, $l_Filename);

			$l_TSEndScan = microtime(true);
                        if ($l_TSEndScan - $l_TSStartScan >= 0.5) {
			   			   usleep(SCAN_DELAY * 1000);
                        }

			if ($g_SkipNextCheck || $l_CriticalDetected) {
				AddResult($l_Filename, $i);
			}
}

function AddResult($l_Filename, $i)
{
	global $g_Structure, $g_CRC;
	
	$l_Stat = stat($l_Filename);
	$g_Structure['n'][$i] = $l_Filename;
	$g_Structure['s'][$i] = $l_Stat['size'];
	$g_Structure['c'][$i] = $l_Stat['ctime'];
	$g_Structure['m'][$i] = $l_Stat['mtime'];
	$g_Structure['crc'][$i] = $g_CRC;
}

///////////////////////////////////////////////////////////////////////////
function WarningPHP($l_FN, $l_Content, &$l_Pos, &$l_SigId)
{
	   global $g_SusDB,$g_ExceptFlex, $gXX_FlexDBShe, $gX_FlexDBShe, $g_FlexDBShe, $gX_DBShe, $g_DBShe, $g_Base64, $g_Base64Fragment;

  $l_Res = false;

  if (AI_EXTRA_WARN) {
  	foreach ($g_SusDB as $l_Item) {
    	if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
       	 	if (!CheckException($l_Content, $l_Found)) {
           	 	$l_Pos = $l_Found[0][1];
           	 	//$l_SigId = myCheckSum($l_Item);
           	 	$l_SigId = getSigId($l_Found);
           	 	return true;
       	 	}
    	}
  	}
  }

  if (AI_EXPERT < 2) {
    	foreach ($gXX_FlexDBShe as $l_Item) {
      		if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
             	$l_Pos = $l_Found[0][1];
           	    //$l_SigId = myCheckSum($l_Item);
           	    $l_SigId = getSigId($l_Found);
        	    return true;
	  		}
    	}

	}

    if (AI_EXPERT < 1) {
    	foreach ($gX_FlexDBShe as $l_Item) {
      		if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
             	$l_Pos = $l_Found[0][1];
           	 	//$l_SigId = myCheckSum($l_Item);
           	 	$l_SigId = getSigId($l_Found);
        	    return true;
	  		}
    	}

	    $l_Content_lo = strtolower($l_Content);

	    foreach ($gX_DBShe as $l_Item) {
	      $l_Pos = strpos($l_Content_lo, $l_Item);
	      if ($l_Pos !== false) {
	         $l_SigId = myCheckSum($l_Item);
	         return true;
	      }
		}
	}

}

///////////////////////////////////////////////////////////////////////////
function Adware($l_FN, $l_Content, &$l_Pos)
{
  global $g_AdwareSig;

  $l_Res = false;

foreach ($g_AdwareSig as $l_Item) {
    $offset = 0;
    while (preg_match('#' . $l_Item . '#smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
       if (!CheckException($l_Content, $l_Found)) {
           $l_Pos = $l_Found[0][1];
           return true;
       }

       $offset = $l_Found[0][1] + 1;
    }
  }

  return $l_Res;
}

///////////////////////////////////////////////////////////////////////////
function CheckException(&$l_Content, &$l_Found) {
  global $g_ExceptFlex, $gX_FlexDBShe, $gXX_FlexDBShe, $g_FlexDBShe, $gX_DBShe, $g_DBShe, $g_Base64, $g_Base64Fragment;
   $l_FoundStrPlus = substr($l_Content, max($l_Found[0][1] - 10, 0), 70);

   foreach ($g_ExceptFlex as $l_ExceptItem) {
      if (@preg_match('#' . $l_ExceptItem . '#smi', $l_FoundStrPlus, $l_Detected)) {
//         print("\n\nEXCEPTION FOUND\n[" . $l_ExceptItem .  "]\n" . $l_Content . "\n\n----------\n\n");
         return true;
      }
   }

   return false;
}

///////////////////////////////////////////////////////////////////////////
function Phishing($l_FN, $l_Index, $l_Content, &$l_SigId)
{
  global $g_PhishingSig, $g_PhishFiles, $g_PhishEntries;

  $l_Res = false;

  // need check file (by extension) ?
  $l_SkipCheck = SMART_SCAN;

if ($l_SkipCheck) {
  	foreach($g_PhishFiles as $l_Ext) {
  		  if (strpos($l_FN, $l_Ext) !== false) {
		  			$l_SkipCheck = false;
		  		  	break;
  	  	  }
  	  }
  }

  // need check file (by signatures) ?
  if ($l_SkipCheck && preg_match('~' . $g_PhishEntries . '~smiS', $l_Content, $l_Found)) {
	  $l_SkipCheck = false;
  }

  if ($l_SkipCheck && SMART_SCAN) {
      if (DEBUG_MODE) {
         echo "Skipped phs file, not critical.\n";
      }

	  return false;
  }


  foreach ($g_PhishingSig as $l_Item) {
    $offset = 0;
    while (preg_match('#' . $l_Item . '#smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
       if (!CheckException($l_Content, $l_Found)) {
           $l_Pos = $l_Found[0][1];
//           $l_SigId = myCheckSum($l_Item);
           $l_SigId = getSigId($l_Found);

           if (DEBUG_MODE) {
              echo "Phis: $l_FN matched [$l_Item] in $l_Pos\n";
           }

           return $l_Pos;
       }
       $offset = $l_Found[0][1] + 1;

    }
  }

  return $l_Res;
}

///////////////////////////////////////////////////////////////////////////
function CriticalJS($l_FN, $l_Index, $l_Content, &$l_SigId)
{
  global $g_JSVirSig, $gX_JSVirSig, $g_VirusFiles, $g_VirusEntries, $g_RegExpStat;

  $l_Res = false;
  
    // need check file (by extension) ?
    $l_SkipCheck = SMART_SCAN;
	
	if ($l_SkipCheck) {
       	   foreach($g_VirusFiles as $l_Ext) {
    		  if (strpos($l_FN, $l_Ext) !== false) {
  		  			$l_SkipCheck = false;
  		  		  	break;
    	  	  }
    	  }
	  }
  
    // need check file (by signatures) ?
    if ($l_SkipCheck && preg_match('~' . $g_VirusEntries . '~smiS', $l_Content, $l_Found)) {
  	  $l_SkipCheck = false;
    }
  
    if ($l_SkipCheck && SMART_SCAN) {
        if (DEBUG_MODE) {
           echo "Skipped js file, not critical.\n";
        }

  	  return false;
    }
  

  foreach ($g_JSVirSig as $l_Item) {
    $offset = 0;
    if (DEBUG_PERFORMANCE) { 
       $stat_start = microtime(true);
    }

    while (preg_match('#' . $l_Item . '#smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {

       if (!CheckException($l_Content, $l_Found)) {
           $l_Pos = $l_Found[0][1];
//           $l_SigId = myCheckSum($l_Item);
           $l_SigId = getSigId($l_Found);

           if (DEBUG_MODE) {
              echo "JS: $l_FN matched [$l_Item] in $l_Pos\n";
           }

           return $l_Pos;
       }

       $offset = $l_Found[0][1] + 1;

    }

    if (DEBUG_PERFORMANCE) { 
       $stat_stop = microtime(true);
       $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
    }
//   if (pcre_error($l_FN, $l_Index)) {  }

  }

if (AI_EXPERT > 1) {
  foreach ($gX_JSVirSig as $l_Item) {
    if (DEBUG_PERFORMANCE) { 
       $stat_start = microtime(true);
    }

    if (preg_match('#' . $l_Item . '#smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
       if (!CheckException($l_Content, $l_Found)) {
           $l_Pos = $l_Found[0][1];
           //$l_SigId = myCheckSum($l_Item);
           $l_SigId = getSigId($l_Found);

           if (DEBUG_MODE) {
              echo "JS PARA: $l_FN matched [$l_Item] in $l_Pos\n";
           }

           return $l_Pos;
       }
    }

    if (DEBUG_PERFORMANCE) { 
       $stat_stop = microtime(true);
       $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
    }

//   if (pcre_error($l_FN, $l_Index)) {  }

  }
}

  return $l_Res;
}

////////////////////////////////////////////////////////////////////////////
function pcre_error($par_FN, $par_Index) {
   global $g_NotRead, $g_Structure;

   $err = preg_last_error();
   if (($err == PREG_BACKTRACK_LIMIT_ERROR) || ($err == PREG_RECURSION_LIMIT_ERROR)) {
      if (!in_array($par_Index, $g_NotRead)) {
         if (function_exists('aibolit_onReadError')) { aibolit_onReadError($l_Filename, 're'); }
         $g_NotRead[] = $par_Index;
         AddResult('[re] ' . $par_FN, $par_Index);
      }
 
      return true;
   }

   return false;
}



////////////////////////////////////////////////////////////////////////////
define('SUSP_MTIME', 1); // suspicious mtime (greater than ctime)
define('SUSP_PERM', 2); // suspicious permissions 
define('SUSP_PHP_IN_UPLOAD', 3); // suspicious .php file in upload or image folder 

  function get_descr_heur($type) {
     switch ($type) {
	     case SUSP_MTIME: return AI_STR_077; 
	     case SUSP_PERM: return AI_STR_078;  
	     case SUSP_PHP_IN_UPLOAD: return AI_STR_079; 
	 }
	 
	 return "---";
  }

  ///////////////////////////////////////////////////////////////////////////
  function HeuristicChecker($l_Content, &$l_Type, $l_Filename) {
     $res = false;
	 
	 $l_Stat = stat($l_Filename);
	 // most likely changed by touch
	 if ($l_Stat['ctime'] < $l_Stat['mtime']) {
	     $l_Type = SUSP_MTIME;
		 return true;
	 }

	 	 
	 $l_Perm = fileperms($l_Filename) & 0777;
	 if (($l_Perm & 0400 != 0400) || // not readable by owner
		($l_Perm == 0000) ||
		($l_Perm == 0404) ||
		($l_Perm == 0505))
	 {
		 $l_Type = SUSP_PERM;
		 return true;
	 }

	 
     if ((strpos($l_Filename, '.ph')) && (
	     strpos($l_Filename, '/images/stories/') ||
	     //strpos($l_Filename, '/img/') ||
		 //strpos($l_Filename, '/images/') ||
	     //strpos($l_Filename, '/uploads/') ||
		 strpos($l_Filename, '/wp-content/upload/') 
	    )	    
	 ) {
		$l_Type = SUSP_PHP_IN_UPLOAD;
	 	return true;
	 }

     return false;
  }

///////////////////////////////////////////////////////////////////////////
function CriticalPHP($l_FN, $l_Index, $l_Content, &$l_Pos, &$l_SigId)
{
  global $g_ExceptFlex, $gXX_FlexDBShe, $gX_FlexDBShe, $g_FlexDBShe, $gX_DBShe, $g_DBShe, $g_Base64, $g_Base64Fragment,
  $g_CriticalFiles, $g_CriticalEntries, $g_RegExpStat;

  // need check file (by extension) ?
  $l_SkipCheck = SMART_SCAN;

  if ($l_SkipCheck) {
	  foreach($g_CriticalFiles as $l_Ext) {
  	  	if ((strpos($l_FN, $l_Ext) !== false) && (strpos($l_FN, '.js') === false)) {
		   $l_SkipCheck = false;
		   break;
  	  	}
  	  }
  }
  
  // need check file (by signatures) ?
  if ($l_SkipCheck && preg_match('~' . $g_CriticalEntries . '~smiS', $l_Content, $l_Found)) {
     $l_SkipCheck = false;
  }
  
  
  // if not critical - skip it 
  if ($l_SkipCheck && SMART_SCAN) {
      if (DEBUG_MODE) {
         echo "Skipped file, not critical.\n";
      }

	  return false;
  }

  foreach ($g_FlexDBShe as $l_Item) {
    $offset = 0;

    if (DEBUG_PERFORMANCE) { 
       $stat_start = microtime(true);
    }

    while (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
       if (!CheckException($l_Content, $l_Found)) {
           $l_Pos = $l_Found[0][1];
           //$l_SigId = myCheckSum($l_Item);
           $l_SigId = getSigId($l_Found);

           if (DEBUG_MODE) {
              echo "CRIT 1: $l_FN matched [$l_Item] in $l_Pos\n";
           }

           return true;
       }

       $offset = $l_Found[0][1] + 1;

    }

    if (DEBUG_PERFORMANCE) { 
       $stat_stop = microtime(true);
       $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
    }

//   if (pcre_error($l_FN, $l_Index)) {  }

  }

if (AI_EXPERT > 0) {
  foreach ($gX_FlexDBShe as $l_Item) {
    if (DEBUG_PERFORMANCE) { 
       $stat_start = microtime(true);
    }

    if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
       if (!CheckException($l_Content, $l_Found)) {
           $l_Pos = $l_Found[0][1];
           //$l_SigId = myCheckSum($l_Item);
           $l_SigId = getSigId($l_Found);

           if (DEBUG_MODE) {
              echo "CRIT 3: $l_FN matched [$l_Item] in $l_Pos\n";
           }

           return true;
       }
    }

    if (DEBUG_PERFORMANCE) { 
       $stat_stop = microtime(true);
       $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
    }

//   if (pcre_error($l_FN, $l_Index)) {  }
  }
}

if (AI_EXPERT > 1) {
  foreach ($gXX_FlexDBShe as $l_Item) {
    if (DEBUG_PERFORMANCE) { 
       $stat_start = microtime(true);
    }

    if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
       if (!CheckException($l_Content, $l_Found)) {
           $l_Pos = $l_Found[0][1];
           //$l_SigId = myCheckSum($l_Item);
           $l_SigId = getSigId($l_Found);

           if (DEBUG_MODE) {
              echo "CRIT 2: $l_FN matched [$l_Item] in $l_Pos\n";
           }

           return true;
       }
    }

    if (DEBUG_PERFORMANCE) { 
       $stat_stop = microtime(true);
       $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
    }

//   if (pcre_error($l_FN, $l_Index)) {  }
  }
}

  $l_Content_lo = strtolower($l_Content);

  foreach ($g_DBShe as $l_Item) {
    $l_Pos = strpos($l_Content_lo, $l_Item);
    if ($l_Pos !== false) {
       $l_SigId = myCheckSum($l_Item);

       if (DEBUG_MODE) {
          echo "CRIT 4: $l_FN matched [$l_Item] in $l_Pos\n";
       }

       return true;
    }
  }

if (AI_EXPERT > 0) {
  foreach ($gX_DBShe as $l_Item) {
    $l_Pos = strpos($l_Content_lo, $l_Item);
    if ($l_Pos !== false) {
       $l_SigId = myCheckSum($l_Item);

       if (DEBUG_MODE) {
          echo "CRIT 5: $l_FN matched [$l_Item] in $l_Pos\n";
       }

       return true;
    }
  }
}

if (AI_HOSTER) return false;

if (AI_EXPERT > 0) {
  if ((strpos($l_Content, 'GIF89') === 0) && (strpos($l_FN, '.php') !== false )) {
     $l_Pos = 0;

     if (DEBUG_MODE) {
          echo "CRIT 6: $l_FN matched [$l_Item] in $l_Pos\n";
     }

     return true;
  }
}

  // detect uploaders / droppers
if (AI_EXPERT > 1) {
  $l_Found = null;
  if (
     (filesize($l_FN) < 1024) &&
     (strpos($l_FN, '.ph') !== false) &&
     (
       (($l_Pos = strpos($l_Content, 'multipart/form-data')) > 0) || 
       (($l_Pos = strpos($l_Content, '$_FILE[') > 0)) ||
       (($l_Pos = strpos($l_Content, 'move_uploaded_file')) > 0) ||
       (preg_match('|\bcopy\s*\(|smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE))
     )
     ) {
       if ($l_Found != null) {
          $l_Pos = $l_Found[0][1];
       } 
     if (DEBUG_MODE) {
          echo "CRIT 7: $l_FN matched [$l_Item] in $l_Pos\n";
     }

     return true;
  }
}

  return false;
}

///////////////////////////////////////////////////////////////////////////
if (!isCli()) {
   header('Content-type: text/html; charset=utf-8');
}

if (!isCli()) {

  $l_PassOK = false;
  if (strlen(PASS) > 8) {
     $l_PassOK = true;   
  } 

  if ($l_PassOK && preg_match('|[0-9]|', PASS, $l_Found) && preg_match('|[A-Z]|', PASS, $l_Found) && preg_match('|[a-z]|', PASS, $l_Found) ) {
     $l_PassOK = true;   
  }
  
  if (!$l_PassOK) {  
    echo sprintf(AI_STR_009, generatePassword());
    exit;
  }

  if (isset($_GET['fn']) && ($_GET['ph'] == crc32(PASS))) {
     printFile();
     exit;
  }

  if ($_GET['p'] != PASS) {
    $generated_pass = generatePassword(); 
    echo sprintf(AI_STR_010, $generated_pass, $generated_pass);
    exit;
  }
}

if (!is_readable(ROOT_PATH)) {
  echo AI_STR_011;
  exit;
}

if (isCli()) {
	if (defined('REPORT_PATH') AND REPORT_PATH)
	{
		if (!is_writable(REPORT_PATH))
		{
			die2("\nCannot write report. Report dir " . REPORT_PATH . " is not writable.");
		}

		else if (!REPORT_FILE)
		{
			die2("\nCannot write report. Report filename is empty.");
		}

		else if (($file = REPORT_PATH . DIR_SEPARATOR . REPORT_FILE) AND is_file($file) AND !is_writable($file))
		{
			die2("\nCannot write report. Report file '$file' exists but is not writable.");
		}
	}
}


// detect version CMS
$g_KnownCMS = array();
$tmp_cms = array();
$g_CmsListDetector = new CmsVersionDetector(ROOT_PATH);
$l_CmsDetectedNum = $g_CmsListDetector->getCmsNumber();
for ($tt = 0; $tt < $l_CmsDetectedNum; $tt++) {
    $g_CMS[] = $g_CmsListDetector->getCmsName($tt) . ' v' . makeSafeFn($g_CmsListDetector->getCmsVersion($tt));
    $tmp_cms[strtolower($g_CmsListDetector->getCmsName($tt))] = 1;
}

if (count($tmp_cms) > 0) {
   $g_KnownCMS = array_keys($tmp_cms);
   $len = count($g_KnownCMS);
   for ($i = 0; $i < $len; $i++) {
      if ($g_KnownCMS[$i] == strtolower(CMS_WORDPRESS)) $g_KnownCMS[] = 'wp';
      if ($g_KnownCMS[$i] == strtolower(CMS_WEBASYST)) $g_KnownCMS[] = 'shopscript';
      if ($g_KnownCMS[$i] == strtolower(CMS_IPB)) $g_KnownCMS[] = 'ipb';
      if ($g_KnownCMS[$i] == strtolower(CMS_DLE)) $g_KnownCMS[] = 'dle';
      if ($g_KnownCMS[$i] == strtolower(CMS_INSTANTCMS)) $g_KnownCMS[] = 'instantcms';
      if ($g_KnownCMS[$i] == strtolower(CMS_SHOPSCRIPT)) $g_KnownCMS[] = 'shopscript';
      if ($g_KnownCMS[$i] == strtolower(CMS_DRUPAL)) $g_KnownCMS[] = 'drupal';
   }
}


$g_DirIgnoreList = array();
$g_IgnoreList = array();
$g_UrlIgnoreList = array();
$g_KnownList = array();

$l_IgnoreFilename = $g_AiBolitAbsolutePath . '/.aignore';
$l_DirIgnoreFilename = $g_AiBolitAbsolutePath . '/.adirignore';
$l_UrlIgnoreFilename = $g_AiBolitAbsolutePath . '/.aurlignore';

if (file_exists($l_IgnoreFilename)) {
    $l_IgnoreListRaw = file($l_IgnoreFilename);
    for ($i = 0; $i < count($l_IgnoreListRaw); $i++) 
    {
    	$g_IgnoreList[] = explode("\t", trim($l_IgnoreListRaw[$i]));
    }
    unset($l_IgnoreListRaw);
}

if (file_exists($l_DirIgnoreFilename)) {
    $g_DirIgnoreList = file($l_DirIgnoreFilename);
	
	for ($i = 0; $i < count($g_DirIgnoreList); $i++) {
		$g_DirIgnoreList[$i] = trim($g_DirIgnoreList[$i]);
	}
}

if (file_exists($l_UrlIgnoreFilename)) {
    $g_UrlIgnoreList = file($l_UrlIgnoreFilename);
	
	for ($i = 0; $i < count($g_UrlIgnoreList); $i++) {
		$g_UrlIgnoreList[$i] = trim($g_UrlIgnoreList[$i]);
	}
}


$l_SkipMask = array(
            '/template_\w{32}.css',
            '/cache/templates/.{1,150}\.tpl\.php',
	    '/system/cache/templates_c/\w{1,40}\.php',
	    '/assets/cache/rss/\w{1,60}',
            '/cache/minify/minify_\w{32}',
            '/cache/page/\w{32}\.php',
            '/cache/object/\w{1,10}/\w{1,10}/\w{1,10}/\w{32}\.php',
            '/cache/wp-cache-\d{32}\.php',
            '/cache/page/\w{32}\.php_expire',
	    '/cache/page/\w{32}-cache-page-\w{32}\.php',
	    '\w{32}-cache-com_content-\w{32}\.php',
	    '\w{32}-cache-mod_custom-\w{32}\.php',
	    '\w{32}-cache-mod_templates-\w{32}\.php',
            '\w{32}-cache-_system-\w{32}\.php',
            '/cache/twig/\w{1,32}/\d+/\w{1,100}\.php', 
            '/autoptimize/js/autoptimize_\w{32}\.js',
            '/bitrix/cache/\w{32}\.php',
            '/bitrix/cache/.+/\w{32}\.php',
            '/bitrix/cache/iblock_find/',
            '/bitrix/managed_cache/MYSQL/user_option/[^/]+/',
            '/bitrix/cache/s1/bitrix/catalog\.section/',
            '/bitrix/cache/s1/bitrix/catalog\.element/',
            '/bitrix/cache/s1/bitrix/menu/',
            '/catalog.element/[^/]+/[^/]+/\w{32}\.php',
            '/bitrix/managed\_cache/.*/\.\w{32}\.php',
            '/core/cache/mgr/smarty/default/.{1,100}\.tpl\.php',
            '/core/cache/resource/web/resources/[0-9]{1,50}\.cache\.php',
            '/smarty/compiled/SC/.*/%%.*\.php',
            '/smarty/.{1,150}\.tpl\.php',
            '/smarty/compile/.{1,150}\.tpl\.cache\.php',
            '/files/templates_c/.{1,150}\.html\.php',
            '/uploads/javascript_global/.{1,150}\.js',
            '/assets/cache/rss/\w{32}',
	    '/assets/cache/docid_\d+_\w{32}\.pageCache\.php',
            '/t3-assets/dev/t3/.*-cache-\w{1,20}-.{1,150}\.php',
	    '/t3-assets/js/js-\w{1,30}\.js',
            '/temp/cache/SC/.*/\.cache\..*\.php',
            '/tmp/sess\_\w{32}$',
            '/assets/cache/docid\_.*\.pageCache\.php',
            '/stat/usage\_\w+\.html',
            '/stat/site\_\w+\.html',
            '/gallery/item/list/\w+\.cache\.php',
            '/core/cache/registry/.*/ext-.*\.php',
            '/core/cache/resource/shk\_/\w+\.cache\.php',
            '/webstat/awstats.*\.txt',
            '/awstats/awstats.*\.txt',
            '/awstats/.{1,80}\.pl',
            '/awstats/.{1,80}\.html',
            '/inc/min/styles_\w+\.min\.css',
            '/inc/min/styles_\w+\.min\.js',
            '/logs/error\_log\..*',
            '/logs/xferlog\..*',
            '/logs/access_log\..*',
            '/logs/cron\..*',
            '/logs/exceptions/.+\.log$',
            '/hyper-cache/[^/]+/[^/]+/[^/]+/index\.html',
            '/mail/new/[^,]+,S=[^,]+,W=.+',
            '/mail/new/[^,]=,S=.+',
            '/application/logs/\d+/\d+/\d+\.php',
            '/sites/default/files/js/js_\w{32}\.js',
            '/yt-assets/\w{32}\.css',
);

$l_SkipSample = array();

if (SMART_SCAN) {
   $g_DirIgnoreList = array_merge($g_DirIgnoreList, $l_SkipMask);
}

QCR_Debug();

// Load custom signatures

try {
	$s_file = new SplFileObject($g_AiBolitAbsolutePath."/ai-bolit.sig");
	$s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
	foreach ($s_file as $line) {
		$g_FlexDBShe[] = preg_replace('~\G(?:[^#\\\\]+|\\\\.)*+\K#~', '\\#', $line); // escaping #
	}
	stdOut("Loaded " . $s_file->key() . " signatures from ai-bolit.sig");
	$s_file = null; // file handler is closed
} catch (Exception $e) { QCR_Debug( "Import ai-bolit.sig " . $e->getMessage() ); }

QCR_Debug();

	$defaults['skip_ext'] = strtolower(trim($defaults['skip_ext']));
         if ($defaults['skip_ext'] != '') {
	    $g_IgnoredExt = explode(',', $defaults['skip_ext']);
	    for ($i = 0; $i < count($g_IgnoredExt); $i++) {
                $g_IgnoredExt[$i] = trim($g_IgnoredExt[$i]);
             }

	    QCR_Debug('Skip files with extensions: ' . implode(',', $g_IgnoredExt));
	    stdOut('Skip extensions: ' . implode(',', $g_IgnoredExt));
         } 

// scan single file
if (defined('SCAN_FILE')) {
   if (file_exists(SCAN_FILE) && is_file(SCAN_FILE) && is_readable(SCAN_FILE)) {
       stdOut("Start scanning file '" . SCAN_FILE . "'.");
       QCR_ScanFile(SCAN_FILE); 
   } else { 
       stdOut("Error:" . SCAN_FILE . " either is not a file or readable");
   }
} else {
	if (isset($_GET['2check'])) {
		$options['with-2check'] = 1;
	}
   
   // scan list of files from file
   if (!(ICHECK || IMAKE) && isset($options['with-2check']) && file_exists(DOUBLECHECK_FILE)) {
      stdOut("Start scanning the list from '" . DOUBLECHECK_FILE . "'.\n");
      $lines = file(DOUBLECHECK_FILE);
      for ($i = 0, $size = count($lines); $i < $size; $i++) {
         $lines[$i] = trim($lines[$i]);
         if (empty($lines[$i])) unset($lines[$i]);
      }
      /* skip first line with <?php die("Forbidden"); ?> */
      unset($lines[0]);
      $g_FoundTotalFiles = count($lines);
      $i = 1;
      foreach ($lines as $l_FN) {
         is_dir($l_FN) && $g_TotalFolder++;
         printProgress( $i++, $l_FN);
         $BOOL_RESULT = true; // display disable
         is_file($l_FN) && QCR_ScanFile($l_FN, $i);
         $BOOL_RESULT = false; // display enable
      }

      $g_FoundTotalDirs = $g_TotalFolder;
      $g_FoundTotalFiles = $g_TotalFiles;

   } else {
      // scan whole file system
      stdOut("Start scanning '" . ROOT_PATH . "'.\n");
      
      file_exists(QUEUE_FILENAME) && unlink(QUEUE_FILENAME);
      if (ICHECK || IMAKE) {
      // INTEGRITY CHECK
        IMAKE and unlink(INTEGRITY_DB_FILE);
        ICHECK and load_integrity_db();
        QCR_IntegrityCheck(ROOT_PATH);
        stdOut("Found $g_FoundTotalFiles files in $g_FoundTotalDirs directories.");
        if (IMAKE) exit(0);
        if (ICHECK) {
            $i = $g_Counter;
            $g_CRC = 0;
            $changes = array();
            $ref =& $g_IntegrityDB;
            foreach ($g_IntegrityDB as $l_FileName => $type) {
                unset($g_IntegrityDB[$l_FileName]);
                $l_Ext2 = substr(strstr(basename($l_FileName), '.'), 1);
                if (in_array(strtolower($l_Ext2), $g_IgnoredExt)) {
                    continue;
                }
                for ($dr = 0; $dr < count($g_DirIgnoreList); $dr++) {
                    if (($g_DirIgnoreList[$dr] != '') && preg_match('#' . $g_DirIgnoreList[$dr] . '#', $l_FileName, $l_Found)) {
                        continue 2;
                    }
                }
                $type = in_array($type, array('added', 'modified')) ? $type : 'deleted';
                $type .= substr($l_FileName, -1) == '/' ? 'Dirs' : 'Files';
                $changes[$type][] = ++$i;
                AddResult($l_FileName, $i);
            }
            $g_FoundTotalFiles = count($changes['addedFiles']) + count($changes['modifiedFiles']);
            stdOut("Found changes " . count($changes['modifiedFiles']) . " files and added " . count($changes['addedFiles']) . " files.");
        }
        
      } else {
      QCR_ScanDirectories(ROOT_PATH);
      stdOut("Found $g_FoundTotalFiles files in $g_FoundTotalDirs directories.");
      }

      QCR_Debug();
      stdOut(str_repeat(' ', 160),false);
      QCR_GoScan(0);
      unlink(QUEUE_FILENAME);
      if (defined('PROGRESS_LOG_FILE') && file_exists(PROGRESS_LOG_FILE)) @unlink(PROGRESS_LOG_FILE);
   }
}

QCR_Debug();

if (true) {
   $g_HeuristicDetected = array();
   $g_Iframer = array();
   $g_Base64 = array();
}


// whitelist

$snum = 0;
$list = check_whitelist($g_Structure['crc'], $snum);

foreach (array('g_CriticalPHP', 'g_CriticalJS', 'g_Iframer', 'g_Base64', 'g_Phishing', 'g_AdwareList', 'g_Redirect') as $p) {
	if (empty($$p)) continue;
	
	$p_Fragment = $p . "Fragment";
	$p_Sig = $p . "Sig";
	if ($p == 'g_Redirect') $p_Fragment = $p . "PHPFragment";
	if ($p == 'g_Phishing') $p_Sig = $p . "SigFragment";

	$count = count($$p);
	for ($i = 0; $i < $count; $i++) {
		$id = "{${$p}[$i]}";
		if (in_array($g_Structure['crc'][$id], $list)) {
			unset($GLOBALS[$p][$i]);
			unset($GLOBALS[$p_Sig][$i]);
			unset($GLOBALS[$p_Fragment][$i]);
		}
	}

	$$p = array_values($$p);
	$$p_Fragment = array_values($$p_Fragment);
	if (!empty($$p_Sig)) $$p_Sig = array_values($$p_Sig);
}


////////////////////////////////////////////////////////////////////////////
if (AI_HOSTER) {
   $g_IframerFragment = array();
   $g_Iframer = array();
   $g_Redirect = array();
   $g_Doorway = array();
   $g_EmptyLink = array();
   $g_HeuristicType = array();
   $g_HeuristicDetected = array();
   $g_WarningPHP = array();
   $g_AdwareList = array();
   $g_Phishing = array(); 
   $g_PHPCodeInside = array();
   $g_PHPCodeInsideFragment = array();
   //$g_NotRead = array();
   $g_WarningPHPFragment = array();
   $g_WarningPHPSig = array();
   $g_BigFiles = array();
   $g_RedirectPHPFragment = array();
   $g_EmptyLinkSrc = array();
   $g_Base64Fragment = array();
   $g_UnixExec = array();
   $g_PhishingSigFragment = array();
   $g_PhishingFragment = array();
   $g_PhishingSig = array();
   $g_IframerFragment = array();
   $g_CMS = array();
   $g_AdwareListFragment = array(); 
   //$g_Vulnerable = array();
}

 if (BOOL_RESULT && (!defined('NEED_REPORT'))) {
  if ((count($g_CriticalPHP) > 0) OR (count($g_CriticalJS) > 0) OR (count($g_Base64) > 0) OR  (count($g_Iframer) > 0) OR  (count($g_UnixExec) > 0))
  {
  echo "1\n";
  exit(0);
  }
 }
////////////////////////////////////////////////////////////////////////////
$l_Template = str_replace("@@SERVICE_INFO@@", htmlspecialchars("[" . $int_enc . "][" . $snum . "]"), $l_Template);

$l_Template = str_replace("@@PATH_URL@@", (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : $g_AddPrefix . str_replace($g_NoPrefix, '', addSlash(ROOT_PATH))), $l_Template);

$time_taken = seconds2Human(microtime(true) - START_TIME);

$l_Template = str_replace("@@SCANNED@@", sprintf(AI_STR_013, $g_TotalFolder, $g_TotalFiles), $l_Template);

$l_ShowOffer = false;

stdOut("\nBuilding report [ mode = " . AI_EXPERT . " ]\n");

//stdOut("\nLoaded signatures: " . count($g_FlexDBShe) . " / " . count($g_JSVirSig) . "\n");

////////////////////////////////////////////////////////////////////////////
// save 
if (!(ICHECK || IMAKE))
if (isset($options['with-2check']) || isset($options['quarantine']))
if ((count($g_CriticalPHP) > 0) OR (count($g_CriticalJS) > 0) OR (count($g_Base64) > 0) OR 
   (count($g_Iframer) > 0) OR  (count($g_UnixExec))) 
{
  if (!file_exists(DOUBLECHECK_FILE)) {	  
      if ($l_FH = fopen(DOUBLECHECK_FILE, 'w')) {
         fputs($l_FH, '<?php die("Forbidden"); ?>' . "\n");

         $l_CurrPath = dirname(__FILE__);
		 
		 if (!isset($g_CriticalPHP)) { $g_CriticalPHP = array(); }
		 if (!isset($g_CriticalJS)) { $g_CriticalJS = array(); }
		 if (!isset($g_Iframer)) { $g_Iframer = array(); }
		 if (!isset($g_Base64)) { $g_Base64 = array(); }
		 if (!isset($g_Phishing)) { $g_Phishing = array(); }
		 if (!isset($g_AdwareList)) { $g_AdwareList = array(); }
		 if (!isset($g_Redirect)) { $g_Redirect = array(); }
		 
         $tmpIndex = array_merge($g_CriticalPHP, $g_CriticalJS, $g_Phishing, $g_Base64, $g_Iframer, $g_AdwareList, $g_Redirect);
         $tmpIndex = array_values(array_unique($tmpIndex));

         for ($i = 0; $i < count($tmpIndex); $i++) {
             $tmpIndex[$i] = str_replace($l_CurrPath, '.', $g_Structure['n'][$tmpIndex[$i]]);
         }

         for ($i = 0; $i < count($g_UnixExec); $i++) {
             $tmpIndex[] = str_replace($l_CurrPath, '.', $g_UnixExec[$i]);
         }

         $tmpIndex = array_values(array_unique($tmpIndex));

         for ($i = 0; $i < count($tmpIndex); $i++) {
             fputs($l_FH, $tmpIndex[$i] . "\n");
         }

         fclose($l_FH);
      } else {
         stdOut("Error! Cannot create " . DOUBLECHECK_FILE);
      }      
  } else {
      stdOut(DOUBLECHECK_FILE . ' already exists.');
      if (AI_STR_044 != '') $l_Result .= '<div class="rep">' . AI_STR_044 . '</div>';
  }
 
}

////////////////////////////////////////////////////////////////////////////

$l_Summary = '<div class="title">' . AI_STR_074 . '</div>';
$l_Summary .= '<table cellspacing=0 border=0>';

if (count($g_Redirect) > 0) {
   $l_Summary .= makeSummary(AI_STR_059, count($g_Redirect), "crit");
}

if (count($g_CriticalPHP) > 0) {
   $l_Summary .= makeSummary(AI_STR_060, count($g_CriticalPHP), "crit");
}

if (count($g_CriticalJS) > 0) {
   $l_Summary .= makeSummary(AI_STR_061, count($g_CriticalJS), "crit");
}

if (count($g_Phishing) > 0) {
   $l_Summary .= makeSummary(AI_STR_062, count($g_Phishing), "crit");
}

if (count($g_UnixExec) > 0) {
   $l_Summary .= makeSummary(AI_STR_063, count($g_UnixExec), (AI_EXPERT > 1 ? 'crit' : 'warn'));
}

if (count($g_Iframer) > 0) {
   $l_Summary .= makeSummary(AI_STR_064, count($g_Iframer), "crit");
}

if (count($g_NotRead) > 0) {
   $l_Summary .= makeSummary(AI_STR_066, count($g_NotRead), "crit");
}

if (count($g_Base64) > 0) {
   $l_Summary .= makeSummary(AI_STR_067, count($g_Base64), (AI_EXPERT > 1 ? 'crit' : 'warn'));
}

if (count($g_BigFiles) > 0) {
   $l_Summary .= makeSummary(AI_STR_065, count($g_BigFiles), "warn");
}

if (count($g_HeuristicDetected) > 0) {
   $l_Summary .= makeSummary(AI_STR_068, count($g_HeuristicDetected), "warn");
}

if (count($g_SymLinks) > 0) {
   $l_Summary .= makeSummary(AI_STR_069, count($g_SymLinks), "warn");
}

if (count($g_HiddenFiles) > 0) {
   $l_Summary .= makeSummary(AI_STR_070, count($g_HiddenFiles), "warn");
}

if (count($g_AdwareList) > 0) {
   $l_Summary .= makeSummary(AI_STR_072, count($g_AdwareList), "warn");
}

if (count($g_EmptyLink) > 0) {
   $l_Summary .= makeSummary(AI_STR_073, count($g_EmptyLink), "warn");
}

 $l_Summary .= "</table>";

$l_ArraySummary = array();
$l_ArraySummary["redirect"] = count($g_Redirect);
$l_ArraySummary["critical_php"] = count($g_CriticalPHP);
$l_ArraySummary["critical_js"] = count($g_CriticalJS);
$l_ArraySummary["phishing"] = count($g_Phishing);
$l_ArraySummary["unix_exec"] = count($g_UnixExec);
$l_ArraySummary["iframes"] = count($g_Iframer);
$l_ArraySummary["not_read"] = count($g_NotRead);
$l_ArraySummary["base64"] = count($g_Base64);
$l_ArraySummary["heuristics"] = count($g_HeuristicDetected);
$l_ArraySummary["symlinks"] = count($g_SymLinks);
$l_ArraySummary["big_files_skipped"] = count($g_BigFiles);

 if (function_exists('json_encode')) { $l_Summary .= "<!--[json]" . json_encode($l_ArraySummary) . "[/json]-->"; }

 $l_Summary .= "<div class=details style=\"margin: 20px 20px 20px 0\">" . AI_STR_080 . "</div>\n";

 $l_Template = str_replace("@@SUMMARY@@", $l_Summary, $l_Template);


 $l_Result .= AI_STR_015;
 
 $l_Template = str_replace("@@VERSION@@", AI_VERSION, $l_Template);
 
////////////////////////////////////////////////////////////////////////////



if (function_exists("gethostname") && is_callable("gethostname")) {
  $l_HostName = gethostname();
} else {
  $l_HostName = '???';
}

$l_PlainResult = "# Malware list detected by AI-Bolit (https://revisium.com/ai/) on " . date("d/m/Y H:i:s", time()) . " " . $l_HostName .  "\n\n";

$l_RawReport = array();

$l_RawReport['summary'] = array(
  'scan_path' => $defaults['path'],
  'report_time' => time(),
  'scan_time' => round(microtime(true) - START_TIME, 1),
  'total_files' => $g_FoundTotalFiles,
  'counters' => $l_ArraySummary,
  'ai_version' => AI_VERSION,
);

if (!AI_HOSTER) {
   stdOut("Building list of vulnerable scripts " . count($g_Vulnerable));

   if (count($g_Vulnerable) > 0) {
       $l_Result .= '<div class="note_vir">' . AI_STR_081 . ' (' . count($g_Vulnerable) . ')</div><div class="crit">';
    	foreach ($g_Vulnerable as $l_Item) {
   	    $l_Result .= '<li>' . makeSafeFn($g_Structure['n'][$l_Item['ndx']], true) . ' - ' . $l_Item['id'] . '</li>';
               $l_PlainResult .= '[VULNERABILITY] ' . replacePathArray($g_Structure['n'][$l_Item['ndx']]) . ' - ' . $l_Item['id'] . "\n";
    	}
   	
     $l_Result .= '</div><p>' . PHP_EOL;
     $l_PlainResult .= "\n";
   }
}


stdOut("Building list of shells " . count($g_CriticalPHP));

$l_RawReport['vulners'] = getRawJsonVuln($g_Vulnerable);

if (count($g_CriticalPHP) > 0) {
  $g_CriticalPHP = array_slice($g_CriticalPHP, 0, 15000);
  $l_RawReport['php_malware'] = getRawJson($g_CriticalPHP, $g_CriticalPHPFragment, $g_CriticalPHPSig);
  $l_Result .= '<div class="note_vir">' . AI_STR_016 . ' (' . count($g_CriticalPHP) . ')</div><div class="crit">';
  $l_Result .= printList($g_CriticalPHP, $g_CriticalPHPFragment, true, $g_CriticalPHPSig, 'table_crit');
  $l_PlainResult .= '[SERVER MALWARE]' . "\n" . printPlainList($g_CriticalPHP, $g_CriticalPHPFragment, true, $g_CriticalPHPSig, 'table_crit') . "\n";
  $l_Result .= '</div>' . PHP_EOL;

  $l_ShowOffer = true;
} else {
  $l_Result .= '<div class="ok"><b>' . AI_STR_017. '</b></div>';
}

stdOut("Building list of js " . count($g_CriticalJS));

if (count($g_CriticalJS) > 0) {
  $g_CriticalJS = array_slice($g_CriticalJS, 0, 15000);
  $l_RawReport['js_malware'] = getRawJson($g_CriticalJS, $g_CriticalJSFragment, $g_CriticalJSSig);
  $l_Result .= '<div class="note_vir">' . AI_STR_018 . ' (' . count($g_CriticalJS) . ')</div><div class="crit">';
  $l_Result .= printList($g_CriticalJS, $g_CriticalJSFragment, true, $g_CriticalJSSig, 'table_vir');
  $l_PlainResult .= '[CLIENT MALWARE / JS]'  . "\n" . printPlainList($g_CriticalJS, $g_CriticalJSFragment, true, $g_CriticalJSSig, 'table_vir') . "\n";
  $l_Result .= "</div>" . PHP_EOL;

  $l_ShowOffer = true;
}

stdOut("Building list of unread files " . count($g_NotRead));

if (count($g_NotRead) > 0) {
   $g_NotRead = array_slice($g_NotRead, 0, AIBOLIT_MAX_NUMBER);
   $l_RawReport['not_read'] = $g_NotRead;
   $l_Result .= '<div class="note_vir">' . AI_STR_030 . ' (' . count($g_NotRead) . ')</div><div class="crit">';
   $l_Result .= printList($g_NotRead);
   $l_Result .= "</div><div class=\"spacer\"></div>" . PHP_EOL;
   $l_PlainResult .= '[SCAN ERROR / SKIPPED]' . "\n" . printPlainList($g_NotRead) . "\n\n";
}

if (!AI_HOSTER) {
   stdOut("Building phishing pages " . count($g_Phishing));

   if (count($g_Phishing) > 0) {
     $l_RawReport['phishing'] = getRawJson($g_Phishing, $g_PhishingFragment, $g_PhishingSigFragment);
     $l_Result .= '<div class="note_vir">' . AI_STR_058 . ' (' . count($g_Phishing) . ')</div><div class="crit">';
     $l_Result .= printList($g_Phishing, $g_PhishingFragment, true, $g_PhishingSigFragment, 'table_vir');
     $l_PlainResult .= '[PHISHING]'  . "\n" . printPlainList($g_Phishing, $g_PhishingFragment, true, $g_PhishingSigFragment, 'table_vir') . "\n";
     $l_Result .= "</div>". PHP_EOL;

     $l_ShowOffer = true;
   }

   stdOut("Building list of iframes " . count($g_Iframer));

   if (count($g_Iframer) > 0) {
     $l_RawReport['iframer'] = getRawJson($g_Iframer, $g_IframerFragment);
     $l_ShowOffer = true;
     $l_Result .= '<div class="note_vir">' . AI_STR_021 . ' (' . count($g_Iframer) . ')</div><div class="crit">';
     $l_Result .= printList($g_Iframer, $g_IframerFragment, true);
     $l_Result .= "</div>" . PHP_EOL;
   }

   stdOut("Building list of base64s " . count($g_Base64));

   if (count($g_Base64) > 0) {
     $l_RawReport['warn_enc'] = getRawJson($g_Base64, $g_Base64Fragment);
     if (AI_EXPERT > 1) $l_ShowOffer = true;
     
     $l_Result .= '<div class="note_' . (AI_EXPERT > 1 ? 'vir' : 'warn') . '">' . AI_STR_020 . ' (' . count($g_Base64) . ')</div><div class="' . (AI_EXPERT > 1 ? 'crit' : 'warn') . '">';
     $l_Result .= printList($g_Base64, $g_Base64Fragment, true);
     $l_PlainResult .= '[ENCODED / SUSP_EXT]' . "\n" . printPlainList($g_Base64, $g_Base64Fragment, true) . "\n";
     $l_Result .= "</div>" . PHP_EOL;

   }

   stdOut("Building list of redirects " . count($g_Redirect));
   if (count($g_Redirect) > 0) {
     $l_RawReport['redirect'] = getRawJson($g_Redirect, $g_RedirectPHPFragment);
     $l_ShowOffer = true;
     $l_Result .= '<div class="note_vir">' . AI_STR_027 . ' (' . count($g_Redirect) . ')</div><div class="crit">';
     $l_Result .= printList($g_Redirect, $g_RedirectPHPFragment, true);
     $l_Result .= "</div>" . PHP_EOL;
   }

   stdOut("Building list of symlinks " . count($g_SymLinks));

   if (count($g_SymLinks) > 0) {
     $g_SymLinks = array_slice($g_SymLinks, 0, AIBOLIT_MAX_NUMBER);
     $l_RawReport['sym_links'] = $g_SymLinks;
     $l_Result .= '<div class="note_vir">' . AI_STR_022 . ' (' . count($g_SymLinks) . ')</div><div class="crit">';
     $l_Result .= nl2br(makeSafeFn(implode("\n", $g_SymLinks), true));
     $l_Result .= "</div><div class=\"spacer\"></div>";
   }

   stdOut("Building list of unix executables and odd scripts " . count($g_UnixExec));

   if (count($g_UnixExec) > 0) {
     $g_UnixExec = array_slice($g_UnixExec, 0, AIBOLIT_MAX_NUMBER);
     $l_RawReport['unix_exec'] = $g_UnixExec;
     $l_Result .= '<div class="note_' . (AI_EXPERT > 1 ? 'vir' : 'warn') . '">' . AI_STR_019 . ' (' . count($g_UnixExec) . ')</div><div class="' . (AI_EXPERT > 1 ? 'crit' : 'warn') . '">';
     $l_Result .= nl2br(makeSafeFn(implode("\n", $g_UnixExec), true));
     $l_PlainResult .= '[UNIX EXEC]' . "\n" . implode("\n", replacePathArray($g_UnixExec)) . "\n\n";
     $l_Result .= "</div>" . PHP_EOL;

     if (AI_EXPERT > 1) $l_ShowOffer = true;
   }
}

////////////////////////////////////
if (!AI_HOSTER) {
   $l_WarningsNum = count($g_HeuristicDetected) + count($g_HiddenFiles) + count($g_BigFiles) + count($g_PHPCodeInside) + count($g_AdwareList) + count($g_EmptyLink) + count($g_Doorway) + (count($g_WarningPHP[0]) + count($g_WarningPHP[1]) + count($g_SkippedFolders));

   if ($l_WarningsNum > 0) {
   	$l_Result .= "<div style=\"margin-top: 20px\" class=\"title\">" . AI_STR_026 . "</div>";
   }

   stdOut("Building list of links/adware " . count($g_AdwareList));

   if (count($g_AdwareList) > 0) {
     $l_RawReport['adware'] = getRawJson($g_AdwareList, $g_AdwareListFragment);
     $l_Result .= '<div class="note_warn">' . AI_STR_029 . '</div><div class="warn">';
     $l_Result .= printList($g_AdwareList, $g_AdwareListFragment, true);
     $l_PlainResult .= '[ADWARE]' . "\n" . printPlainList($g_AdwareList, $g_AdwareListFragment, true) . "\n";
     $l_Result .= "</div>" . PHP_EOL;

   }

   stdOut("Building list of heuristics " . count($g_HeuristicDetected));

   if (count($g_HeuristicDetected) > 0) {
     $l_RawReport['heuristic'] = $g_HeuristicDetected;
     $l_Result .= '<div class="note_warn">' . AI_STR_052 . ' (' . count($g_HeuristicDetected) . ')</div><div class="warn">';
     for ($i = 0; $i < count($g_HeuristicDetected); $i++) {
   	   $l_Result .= '<li>' . makeSafeFn($g_Structure['n'][$g_HeuristicDetected[$i]], true) . ' (' . get_descr_heur($g_HeuristicType[$i]) . ')</li>';
     }
     
     $l_Result .= '</ul></div><div class=\"spacer\"></div>' . PHP_EOL;
   }

   stdOut("Building list of hidden files " . count($g_HiddenFiles));
   if (count($g_HiddenFiles) > 0) {
     $g_HiddenFiles = array_slice($g_HiddenFiles, 0, AIBOLIT_MAX_NUMBER);
     $l_RawReport['hidden'] = $g_HiddenFiles;
     $l_Result .= '<div class="note_warn">' . AI_STR_023 . ' (' . count($g_HiddenFiles) . ')</div><div class="warn">';
     $l_Result .= nl2br(makeSafeFn(implode("\n", $g_HiddenFiles), true));
     $l_Result .= "</div><div class=\"spacer\"></div>" . PHP_EOL;
     $l_PlainResult .= '[HIDDEN]' . "\n" . implode("\n", replacePathArray($g_HiddenFiles)) . "\n\n";
   }

   stdOut("Building list of bigfiles " . count($g_BigFiles));
   $max_size_to_scan = getBytes(MAX_SIZE_TO_SCAN);
   $max_size_to_scan = $max_size_to_scan > 0 ? $max_size_to_scan : getBytes('1m');

   if (count($g_BigFiles) > 0) {
     $g_BigFiles = array_slice($g_BigFiles, 0, AIBOLIT_MAX_NUMBER);
     $l_RawReport['big_files'] = getRawJson($g_BigFiles);
     $l_Result .= "<div class=\"note_warn\">" . sprintf(AI_STR_038, bytes2Human($max_size_to_scan)) . '</div><div class="warn">';
     $l_Result .= printList($g_BigFiles);
     $l_Result .= "</div>";
     $l_PlainResult .= '[BIG FILES / SKIPPED]' . "\n" . printPlainList($g_BigFiles) . "\n\n";
   } 

   stdOut("Building list of php inj " . count($g_PHPCodeInside));

   if ((count($g_PHPCodeInside) > 0) && (($defaults['report_mask'] & REPORT_MASK_PHPSIGN) == REPORT_MASK_PHPSIGN)) {
     $l_Result .= '<div class="note_warn">' . AI_STR_028 . '</div><div class="warn">';
     $l_Result .= printList($g_PHPCodeInside, $g_PHPCodeInsideFragment, true);
     $l_Result .= "</div>" . PHP_EOL;

   }

   stdOut("Building list of empty links " . count($g_EmptyLink));
   if (count($g_EmptyLink) > 0) {
     $g_EmptyLink = array_slice($g_EmptyLink, 0, AIBOLIT_MAX_NUMBER);
     $l_Result .= '<div class="note_warn">' . AI_STR_031 . '</div><div class="warn">';
     $l_Result .= printList($g_EmptyLink, '', true);

     $l_Result .= AI_STR_032 . '<br/>';
     
     if (count($g_EmptyLink) == MAX_EXT_LINKS) {
         $l_Result .= '(' . AI_STR_033 . MAX_EXT_LINKS . ')<br/>';
       }
      
     for ($i = 0; $i < count($g_EmptyLink); $i++) {
   	$l_Idx = $g_EmptyLink[$i];
       for ($j = 0; $j < count($g_EmptyLinkSrc[$l_Idx]); $j++) {
         $l_Result .= '<span class="details">' . makeSafeFn($g_Structure['n'][$g_EmptyLink[$i]], true) . ' &rarr; ' . htmlspecialchars($g_EmptyLinkSrc[$l_Idx][$j]) . '</span><br/>';
   	}
     }

     $l_Result .= "</div>";

   }

   stdOut("Building list of doorways " . count($g_Doorway));

   if ((count($g_Doorway) > 0) && (($defaults['report_mask'] & REPORT_MASK_DOORWAYS) == REPORT_MASK_DOORWAYS)) {
     $g_Doorway = array_slice($g_Doorway, 0, AIBOLIT_MAX_NUMBER);
     $l_RawReport['doorway'] = getRawJson($g_Doorway);
     $l_Result .= '<div class="note_warn">' . AI_STR_034 . '</div><div class="warn">';
     $l_Result .= printList($g_Doorway);
     $l_Result .= "</div>" . PHP_EOL;

   }

   stdOut("Building list of php warnings " . (count($g_WarningPHP[0]) + count($g_WarningPHP[1])));

   if (($defaults['report_mask'] & REPORT_MASK_SUSP) == REPORT_MASK_SUSP) {
      if ((count($g_WarningPHP[0]) + count($g_WarningPHP[1])) > 0) {
        $g_WarningPHP[0] = array_slice($g_WarningPHP[0], 0, AIBOLIT_MAX_NUMBER);
        $g_WarningPHP[1] = array_slice($g_WarningPHP[1], 0, AIBOLIT_MAX_NUMBER);
        $l_Result .= '<div class="note_warn">' . AI_STR_035 . '</div><div class="warn">';

        for ($i = 0; $i < count($g_WarningPHP); $i++) {
            if (count($g_WarningPHP[$i]) > 0) 
               $l_Result .= printList($g_WarningPHP[$i], $g_WarningPHPFragment[$i], true, $g_WarningPHPSig, 'table_warn' . $i);
        }                                                                                                                    
        $l_Result .= "</div>" . PHP_EOL;

      } 
   }

   stdOut("Building list of skipped dirs " . count($g_SkippedFolders));
   if (count($g_SkippedFolders) > 0) {
        $l_Result .= '<div class="note_warn">' . AI_STR_036 . '</div><div class="warn">';
        $l_Result .= nl2br(makeSafeFn(implode("\n", $g_SkippedFolders), true));   
        $l_Result .= "</div>" . PHP_EOL;
    }

    if (count($g_CMS) > 0) {
         $l_RawReport['cms'] = $g_CMS;
         $l_Result .= "<div class=\"note_warn\">" . AI_STR_037 . "<br/>";
         $l_Result .= nl2br(makeSafeFn(implode("\n", $g_CMS)));
         $l_Result .= "</div>";
    }
}

if (ICHECK) {
	$l_Result .= "<div style=\"margin-top: 20px\" class=\"title\">" . AI_STR_087 . "</div>";
	
    stdOut("Building list of added files " . count($changes['addedFiles']));
    if (count($changes['addedFiles']) > 0) {
      $l_Result .= '<div class="note_int">' . AI_STR_082 . ' (' . count($changes['addedFiles']) . ')</div><div class="intitem">';
      $l_Result .= printList($changes['addedFiles']);
      $l_Result .= "</div>" . PHP_EOL;
    }

    stdOut("Building list of modified files " . count($changes['modifiedFiles']));
    if (count($changes['modifiedFiles']) > 0) {
      $l_Result .= '<div class="note_int">' . AI_STR_083 . ' (' . count($changes['modifiedFiles']) . ')</div><div class="intitem">';
      $l_Result .= printList($changes['modifiedFiles']);
      $l_Result .= "</div>" . PHP_EOL;
    }

    stdOut("Building list of deleted files " . count($changes['deletedFiles']));
    if (count($changes['deletedFiles']) > 0) {
      $l_Result .= '<div class="note_int">' . AI_STR_084 . ' (' . count($changes['deletedFiles']) . ')</div><div class="intitem">';
      $l_Result .= printList($changes['deletedFiles']);
      $l_Result .= "</div>" . PHP_EOL;
    }

    stdOut("Building list of added dirs " . count($changes['addedDirs']));
    if (count($changes['addedDirs']) > 0) {
      $l_Result .= '<div class="note_int">' . AI_STR_085 . ' (' . count($changes['addedDirs']) . ')</div><div class="intitem">';
      $l_Result .= printList($changes['addedDirs']);
      $l_Result .= "</div>" . PHP_EOL;
    }

    stdOut("Building list of deleted dirs " . count($changes['deletedDirs']));
    if (count($changes['deletedDirs']) > 0) {
      $l_Result .= '<div class="note_int">' . AI_STR_086 . ' (' . count($changes['deletedDirs']) . ')</div><div class="intitem">';
      $l_Result .= printList($changes['deletedDirs']);
      $l_Result .= "</div>" . PHP_EOL;
    }
}

if (!isCli()) {
   $l_Result .= QCR_ExtractInfo($l_PhpInfoBody[1]);
}


if (function_exists('memory_get_peak_usage')) {
  $l_Template = str_replace("@@MEMORY@@", AI_STR_043 . bytes2Human(memory_get_peak_usage()), $l_Template);
}

$l_Template = str_replace('@@WARN_QUICK@@', ((SCAN_ALL_FILES || $g_SpecificExt) ? '' : AI_STR_045), $l_Template);

if ($l_ShowOffer) {
	$l_Template = str_replace('@@OFFER@@', $l_Offer, $l_Template);
} else {
	$l_Template = str_replace('@@OFFER@@', AI_STR_002, $l_Template);
}

$l_Template = str_replace('@@OFFER2@@', $l_Offer2, $l_Template);

$l_Template = str_replace('@@CAUTION@@', AI_STR_003, $l_Template);

$l_Template = str_replace('@@CREDITS@@', AI_STR_075, $l_Template);

$l_Template = str_replace('@@FOOTER@@', AI_STR_076, $l_Template);

$l_Template = str_replace('@@STAT@@', sprintf(AI_STR_012, $time_taken, date('d-m-Y в H:i:s', floor(START_TIME)) , date('d-m-Y в H:i:s')), $l_Template);

////////////////////////////////////////////////////////////////////////////
$l_Template = str_replace("@@MAIN_CONTENT@@", $l_Result, $l_Template);

if (!isCli())
{
    echo $l_Template;
    exit;
}

if (!defined('REPORT') OR REPORT === '')
{
	die2('Report not written.');
}
 
// write plain text result
if (PLAIN_FILE != '') {
	
    $l_PlainResult = preg_replace('|__AI_LINE1__|smi', '[', $l_PlainResult);
    $l_PlainResult = preg_replace('|__AI_LINE2__|smi', '] ', $l_PlainResult);
    $l_PlainResult = preg_replace('|__AI_MARKER__|smi', ' %> ', $l_PlainResult);

   if ($l_FH = fopen(PLAIN_FILE, "w")) {
      fputs($l_FH, $l_PlainResult);
      fclose($l_FH);
   }
}

// write json result
if (defined('JSON_FILE')) {	
   if ($l_FH = fopen(JSON_FILE, "w")) {
      fputs($l_FH, json_encode($l_RawReport));
      fclose($l_FH);
   }
}

// write serialized result
if (defined('PHP_FILE')) {	
   if ($l_FH = fopen(PHP_FILE, "w")) {
      fputs($l_FH, serialize($l_RawReport));
      fclose($l_FH);
   }
}

$emails = getEmails(REPORT);

if (!$emails) {
	if ($l_FH = fopen($file, "w")) {
	   fputs($l_FH, $l_Template);
	   fclose($l_FH);
	   stdOut("\nReport written to '$file'.");
	} else {
		stdOut("\nCannot create '$file'.");
	}
}	else	{
		$headers = array(
			'MIME-Version: 1.0',
			'Content-type: text/html; charset=UTF-8',
			'From: ' . ($defaults['email_from'] ? $defaults['email_from'] : 'AI-Bolit@myhost')
		);

		for ($i = 0, $size = sizeof($emails); $i < $size; $i++)
		{
			mail($emails[$i], 'AI-Bolit Report ' . date("d/m/Y H:i", time()), $l_Result, implode("\r\n", $headers));
		}

		stdOut("\nReport sended to " . implode(', ', $emails));
}


$time_taken = microtime(true) - START_TIME;
$time_taken = number_format($time_taken, 5);


stdOut("Scanning complete! Time taken: " . seconds2Human($time_taken));

if (DEBUG_PERFORMANCE) {
   $keys = array_keys($g_RegExpStat);
   for ($i = 0; $i < count($keys); $i++) {
       $g_RegExpStat[$keys[$i]] = round($g_RegExpStat[$keys[$i]] * 1000000);
   }

   arsort($g_RegExpStat);

   foreach ($g_RegExpStat as $r => $v) {
      echo $v . "\t\t" . $r . "\n";
   }

   die();
}

stdOut("\n\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
stdOut("Attention! DO NOT LEAVE either ai-bolit.php or AI-BOLIT-REPORT-<xxxx>-<yy>.html \nfile on server. COPY it locally then REMOVE from server. ");
stdOut("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

if (isset($options['quarantine'])) {
	Quarantine();
}

if (isset($options['cmd'])) {
	stdOut("Run \"{$options['cmd']}\" ");
	system($options['cmd']);
}

QCR_Debug();

# exit with code

$l_EC1 = count($g_CriticalPHP);
$l_EC2 = count($g_CriticalJS) + count($g_Phishing) + count($g_WarningPHP[0]) + count($g_WarningPHP[1]);
$code = 0;

if ($l_EC1 > 0) {
	$code = 2;
} else {
	if ($l_EC2 > 0) {
		$code = 1;
	}
}

$stat = array('php_malware' => count($g_CriticalPHP), 'js_malware' => count($g_CriticalJS), 'phishing' => count($g_Phishing));

if (function_exists('aibolit_onComplete')) { aibolit_onComplete($code, $stat); }

stdOut('Exit code ' . $code);
exit($code);

############################################# END ###############################################

function Quarantine()
{
	if (!file_exists(DOUBLECHECK_FILE)) {
		return;
	}
	
	$g_QuarantinePass = 'aibolit';
	
	$archive = "AI-QUARANTINE-" .rand(100000, 999999) . ".zip";
	$infoFile = substr($archive, 0, -3) . "txt";
	$report = REPORT_PATH . DIR_SEPARATOR . REPORT_FILE;
	

	foreach (file(DOUBLECHECK_FILE) as $file) {
		$file = trim($file);
		if (!is_file($file)) continue;
	
		$lStat = stat($file);
		
		// skip files over 300KB
		if ($lStat['size'] > 300*1024) continue;

		// http://www.askapache.com/security/chmod-stat.html
		$p = $lStat['mode'];
		$perm ='-';
		$perm.=(($p&0x0100)?'r':'-').(($p&0x0080)?'w':'-');
		$perm.=(($p&0x0040)?(($p&0x0800)?'s':'x'):(($p&0x0800)?'S':'-'));
		$perm.=(($p&0x0020)?'r':'-').(($p&0x0010)?'w':'-');
		$perm.=(($p&0x0008)?(($p&0x0400)?'s':'x'):(($p&0x0400)?'S':'-'));
		$perm.=(($p&0x0004)?'r':'-').(($p&0x0002)?'w':'-');
		$perm.=(($p&0x0001)?(($p&0x0200)?'t':'x'):(($p&0x0200)?'T':'-'));
		
		$owner = (function_exists('posix_getpwuid'))? @posix_getpwuid($lStat['uid']) : array('name' => $lStat['uid']);
		$group = (function_exists('posix_getgrgid'))? @posix_getgrgid($lStat['gid']) : array('name' => $lStat['uid']);

		$inf['permission'][] = $perm;
		$inf['owner'][] = $owner['name'];
		$inf['group'][] = $group['name'];
		$inf['size'][] = $lStat['size'] > 0 ? bytes2Human($lStat['size']) : '-';
		$inf['ctime'][] = $lStat['ctime'] > 0 ? date("d/m/Y H:i:s", $lStat['ctime']) : '-';
		$inf['mtime'][] = $lStat['mtime'] > 0 ? date("d/m/Y H:i:s", $lStat['mtime']) : '-';
		$files[] = strpos($file, './') === 0 ? substr($file, 2) : $file;
	}
	
	// get config files for cleaning
	$configFilesRegex = 'config(uration|\.in[ic])?\.php$|dbconn\.php$';
	$configFiles = preg_grep("~$configFilesRegex~", $files);

	// get columns width
	$width = array();
	foreach (array_keys($inf) as $k) {
		$width[$k] = strlen($k);
		for ($i = 0; $i < count($inf[$k]); ++$i) {
			$len = strlen($inf[$k][$i]);
			if ($len > $width[$k])
				$width[$k] = $len;
		}
	}

	// headings of columns
	$info = '';
	foreach (array_keys($inf) as $k) {
		$info .= str_pad($k, $width[$k], ' ', STR_PAD_LEFT). ' ';
	}
	$info .= "name\n";
	
	for ($i = 0; $i < count($files); ++$i) {
		foreach (array_keys($inf) as $k) {
			$info .= str_pad($inf[$k][$i], $width[$k], ' ', STR_PAD_LEFT). ' ';
		}
		$info .= $files[$i]."\n";
	}
	unset($inf, $width);

	exec("zip -v 2>&1", $output,$code);

	if ($code == 0) {
		$filter = '';
		if ($configFiles && exec("grep -V 2>&1", $output, $code) && $code == 0) {
			$filter = "|grep -v -E '$configFilesRegex'";
		}

		exec("cat AI-BOLIT-DOUBLECHECK.php $filter |zip -@ --password $g_QuarantinePass $archive", $output, $code);
		if ($code == 0) {
			file_put_contents($infoFile, $info);
			$m = array();
			if (!empty($filter)) {
				foreach ($configFiles as $file) {
					$tmp = file_get_contents($file);
					// remove  passwords
					$tmp = preg_replace('~^.*?pass.*~im', '', $tmp);
					// new file name
					$file = preg_replace('~.*/~', '', $file) . '-' . rand(100000, 999999);
					file_put_contents($file, $tmp);
					$m[] = $file;
				}
			}

			exec("zip -j --password $g_QuarantinePass $archive $infoFile $report " . DOUBLECHECK_FILE . ' ' . implode(' ', $m));
			stdOut("\nCreate archive '" . realpath($archive) . "'");
			stdOut("This archive have password '$g_QuarantinePass'");
			foreach ($m as $file) unlink($file);
			unlink($infoFile);
			return;
		}
	}
	
	$zip = new ZipArchive;
	
	if ($zip->open($archive, ZIPARCHIVE::CREATE | ZIPARCHIVE::OVERWRITE) === false) {
		stdOut("Cannot create '$archive'.");
		return;
	}

	foreach ($files as $file) {
		if (in_array($file, $configFiles)) {
			$tmp = file_get_contents($file);
			// remove  passwords
			$tmp = preg_replace('~^.*?pass.*~im', '', $tmp);
			$zip->addFromString($file, $tmp);
		} else {
			$zip->addFile($file);
		}
	}
	$zip->addFile(DOUBLECHECK_FILE, DOUBLECHECK_FILE);
	$zip->addFile($report, REPORT_FILE);
	$zip->addFromString($infoFile, $info);
	$zip->close();

	stdOut("\nCreate archive '" . realpath($archive) . "'.");
	stdOut("This archive has no password!");
}



///////////////////////////////////////////////////////////////////////////
function QCR_IntegrityCheck($l_RootDir)
{
	global $g_Structure, $g_Counter, $g_Doorway, $g_FoundTotalFiles, $g_FoundTotalDirs, 
			$defaults, $g_SkippedFolders, $g_UrlIgnoreList, $g_DirIgnoreList, $g_UnsafeDirArray, 
                        $g_UnsafeFilesFound, $g_SymLinks, $g_HiddenFiles, $g_UnixExec, $g_IgnoredExt, $g_SuspiciousFiles, $l_SkipSample;
	global $g_IntegrityDB, $g_ICheck;
	static $l_Buffer = '';
	
	$l_DirCounter = 0;
	$l_DoorwayFilesCounter = 0;
	$l_SourceDirIndex = $g_Counter - 1;
	
	QCR_Debug('Check ' . $l_RootDir);

 	if ($l_DIRH = @opendir($l_RootDir))
	{
		while (($l_FileName = readdir($l_DIRH)) !== false)
		{
			if ($l_FileName == '.' || $l_FileName == '..') continue;

			$l_FileName = $l_RootDir . DIR_SEPARATOR . $l_FileName;

			$l_Type = filetype($l_FileName);
			$l_IsDir = ($l_Type == "dir");
            if ($l_Type == "link") 
            {
				$g_SymLinks[] = $l_FileName;
                continue;
            } else 
			if ($l_Type != "file" && (!$l_IsDir)) {
				$g_UnixExec[] = $l_FileName;
				continue;
			}	
						
			$l_Ext = substr($l_FileName, strrpos($l_FileName, '.') + 1);

			$l_NeedToScan = true;
			$l_Ext2 = substr(strstr(basename($l_FileName), '.'), 1);
			if (in_array(strtolower($l_Ext2), $g_IgnoredExt)) {
                           $l_NeedToScan = false;
            		}

      			// if folder in ignore list
      			$l_Skip = false;
      			for ($dr = 0; $dr < count($g_DirIgnoreList); $dr++) {
      				if (($g_DirIgnoreList[$dr] != '') &&
      				   preg_match('#' . $g_DirIgnoreList[$dr] . '#', $l_FileName, $l_Found)) {
      				   if (!in_array($g_DirIgnoreList[$dr], $l_SkipSample)) {
                                      $l_SkipSample[] = $g_DirIgnoreList[$dr];
                                   } else {
        		             $l_Skip = true;
                                     $l_NeedToScan = false;
                                   }
      				}
      			}
      					
			if (getRelativePath($l_FileName) == "./" . INTEGRITY_DB_FILE) $l_NeedToScan = false;

			if ($l_IsDir)
			{
				// skip on ignore
				if ($l_Skip) {
				   $g_SkippedFolders[] = $l_FileName;
				   continue;
				}
				
				$l_BaseName = basename($l_FileName);

				$l_DirCounter++;

				$g_Counter++;
				$g_FoundTotalDirs++;

				QCR_IntegrityCheck($l_FileName);

			} else
			{
				if ($l_NeedToScan)
				{
					$g_FoundTotalFiles++;
					$g_Counter++;
				}
			}
			
			if (!$l_NeedToScan) continue;

			if (IMAKE) {
				write_integrity_db_file($l_FileName);
				continue;
			}

			// ICHECK
			// skip if known and not modified.
			if (icheck($l_FileName)) continue;
			
			$l_Buffer .= getRelativePath($l_FileName);
			$l_Buffer .= $l_IsDir ? DIR_SEPARATOR . "\n" : "\n";

			if (strlen($l_Buffer) > 32000)
			{
				file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
				$l_Buffer = '';
			}

		}

		closedir($l_DIRH);
	}
	
	if (($l_RootDir == ROOT_PATH) && !empty($l_Buffer)) {
		file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
		$l_Buffer = '';
	}

	if (($l_RootDir == ROOT_PATH)) {
		write_integrity_db_file();
	}

}


function getRelativePath($l_FileName) {
	return "./" . substr($l_FileName, strlen(ROOT_PATH) + 1) . (is_dir($l_FileName) ? DIR_SEPARATOR : '');
}
/**
 *
 * @return true if known and not modified
 */
function icheck($l_FileName) {
	global $g_IntegrityDB, $g_ICheck;
	static $l_Buffer = '';
	static $l_status = array( 'modified' => 'modified', 'added' => 'added' );
    
	$l_RelativePath = getRelativePath($l_FileName);
	$l_known = isset($g_IntegrityDB[$l_RelativePath]);

	if (is_dir($l_FileName)) {
		if ( $l_known ) {
			unset($g_IntegrityDB[$l_RelativePath]);
		} else {
			$g_IntegrityDB[$l_RelativePath] =& $l_status['added'];
		}
		return $l_known;
	}

	if ($l_known == false) {
		$g_IntegrityDB[$l_RelativePath] =& $l_status['added'];
		return false;
	}

	$hash = is_file($l_FileName) ? hash_file('sha1', $l_FileName) : '';
	
	if ($g_IntegrityDB[$l_RelativePath] != $hash) {
		$g_IntegrityDB[$l_RelativePath] =& $l_status['modified'];
		return false;
	}

	unset($g_IntegrityDB[$l_RelativePath]);
	return true;
}

function write_integrity_db_file($l_FileName = '') {
	static $l_Buffer = '';

	if (empty($l_FileName)) {
		empty($l_Buffer) or file_put_contents('compress.zlib://' . INTEGRITY_DB_FILE, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . INTEGRITY_DB_FILE);
		$l_Buffer = '';
		return;
	}

	$l_RelativePath = getRelativePath($l_FileName);
		
	$hash = is_file($l_FileName) ? hash_file('sha1', $l_FileName) : '';

	$l_Buffer .= "$l_RelativePath|$hash\n";
	
	if (strlen($l_Buffer) > 32000)
	{
		file_put_contents('compress.zlib://' . INTEGRITY_DB_FILE, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . INTEGRITY_DB_FILE);
		$l_Buffer = '';
	}
}

function load_integrity_db() {
	global $g_IntegrityDB;
	file_exists(INTEGRITY_DB_FILE) or die2('Not found ' . INTEGRITY_DB_FILE);

	$s_file = new SplFileObject('compress.zlib://'.INTEGRITY_DB_FILE);
	$s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);

	foreach ($s_file as $line) {
		$i = strrpos($line, '|');
		if (!$i) continue;
		$g_IntegrityDB[substr($line, 0, $i)] = substr($line, $i+1);
	}

	$s_file = null;
}


function OptimizeSignatures()
{
	global $g_DBShe, $g_FlexDBShe, $gX_FlexDBShe, $gXX_FlexDBShe;
	global $g_JSVirSig, $gX_JSVirSig;
	global $g_AdwareSig;
	global $g_PhishingSig;
	global $g_ExceptFlex, $g_SusDBPrio, $g_SusDB;

	(AI_EXPERT == 2) && ($g_FlexDBShe = array_merge($g_FlexDBShe, $gX_FlexDBShe, $gXX_FlexDBShe));
	(AI_EXPERT == 1) && ($g_FlexDBShe = array_merge($g_FlexDBShe, $gX_FlexDBShe));
	$gX_FlexDBShe = $gXX_FlexDBShe = array();

	(AI_EXPERT == 2) && ($g_JSVirSig = array_merge($g_JSVirSig, $gX_JSVirSig));
	$gX_JSVirSig = array();

	$count = count($g_FlexDBShe);

	for ($i = 0; $i < $count; $i++) {
		if ($g_FlexDBShe[$i] == '[a-zA-Z0-9_]+?\(\s*[a-zA-Z0-9_]+?=\s*\)') $g_FlexDBShe[$i] = '\((?<=[a-zA-Z0-9_].)\s*[a-zA-Z0-9_]++=\s*\)';
		if ($g_FlexDBShe[$i] == '([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e') $g_FlexDBShe[$i] = '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e';
		if ($g_FlexDBShe[$i] == '$[a-zA-Z0-9_]\{\d+\}\s*\.$[a-zA-Z0-9_]\{\d+\}\s*\.$[a-zA-Z0-9_]\{\d+\}\s*\.') $g_FlexDBShe[$i] = '\$[a-zA-Z0-9_]\{\d+\}\s*\.\$[a-zA-Z0-9_]\{\d+\}\s*\.\$[a-zA-Z0-9_]\{\d+\}\s*\.';

		$g_FlexDBShe[$i] = str_replace('http://.+?/.+?\.php\?a', 'http://[^?\s]++(?<=\.php)\?a', $g_FlexDBShe[$i]);
		$g_FlexDBShe[$i] = preg_replace('~\[a-zA-Z0-9_\]\+\K\?~', '+', $g_FlexDBShe[$i]);
		$g_FlexDBShe[$i] = preg_replace('~^\\\\[d]\+&@~', '&@(?<=\d..)', $g_FlexDBShe[$i]);
		$g_FlexDBShe[$i] = str_replace('\s*[\'"]{0,1}.+?[\'"]{0,1}\s*', '.+?', $g_FlexDBShe[$i]);
		$g_FlexDBShe[$i] = str_replace('[\'"]{0,1}.+?[\'"]{0,1}', '.+?', $g_FlexDBShe[$i]);

		$g_FlexDBShe[$i] = preg_replace('~^\[\'"\]\{0,1\}\.?|^@\*|^\\\\s\*~', '', $g_FlexDBShe[$i]);
		$g_FlexDBShe[$i] = preg_replace('~^\[\'"\]\{0,1\}\.?|^@\*|^\\\\s\*~', '', $g_FlexDBShe[$i]);
	}

	optSig($g_FlexDBShe);

	optSig($g_JSVirSig);
	optSig($g_AdwareSig);
	optSig($g_PhishingSig);
        optSig($g_SusDB);
        //optSig($g_SusDBPrio);
        //optSig($g_ExceptFlex);

        // convert exception rules
        $cnt = count($g_ExceptFlex);
        for ($i = 0; $i < $cnt; $i++) {                		
            $g_ExceptFlex[$i] = trim(UnwrapObfu($g_ExceptFlex[$i]));
            if (!strlen($g_ExceptFlex[$i])) unset($g_ExceptFlex[$i]);
        }

        $g_ExceptFlex = array_values($g_ExceptFlex);
}

function optSig(&$sigs)
{
	$sigs = array_unique($sigs);

	// Add SigId
	foreach ($sigs as &$s) {
		$s .= '(?<X' . myCheckSum($s) . '>)';
	}
	unset($s);
	
	$fix = array(
		'([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e' => '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e',
		'http://.+?/.+?\.php\?a' => 'http://[^?\s]++(?<=\.php)\?a',
		'\s*[\'"]{0,1}.+?[\'"]{0,1}\s*' => '.+?',
		'[\'"]{0,1}.+?[\'"]{0,1}' => '.+?'
	);

	$sigs = str_replace(array_keys($fix), array_values($fix), $sigs);
	
	$fix = array(
		'~^\\\\[d]\+&@~' => '&@(?<=\d..)',
		'~^((\[\'"\]|\\\\s|@)(\{0,1\}\.?|[?*]))+~' => ''
	);

	$sigs = preg_replace(array_keys($fix), array_values($fix), $sigs);

	optSigCheck($sigs);

	$tmp = array();
	foreach ($sigs as $i => $s) {
		if (!preg_match('#^(?>(?!\.[*+]|\\\\\d)(?:\\\\.|\[.+?\]|.))+$#', $s)) {
			unset($sigs[$i]);
			$tmp[] = $s;
		}
	}
	
	usort($sigs, 'strcasecmp');
	$txt = implode("\n", $sigs);

	for ($i = 24; $i >= 1; ($i > 4 ) ? $i -= 4 : --$i) {
	    $txt = preg_replace_callback('#^((?>(?:\\\\.|\\[.+?\\]|[^(\n]|\((?:\\\\.|[^)(\n])++\))(?:[*?+]\+?|\{\d+(?:,\d*)?\}[+?]?|)){' . $i . ',})[^\n]*+(?:\\n\\1(?![{?*+]).+)+#im', 'optMergePrefixes', $txt);
	}

	$sigs = array_merge(explode("\n", $txt), $tmp);
	
	optSigCheck($sigs);
}

function optMergePrefixes($m)
{
	$limit = 8000;
	
	$prefix = $m[1];
	$prefix_len = strlen($prefix);

	$len = $prefix_len;
	$r = array();

	$suffixes = array();
	foreach (explode("\n", $m[0]) as $line) {
	
	  if (strlen($line)>$limit) {
	    $r[] = $line;
	    continue;
	  }
	
	  $s = substr($line, $prefix_len);
	  $len += strlen($s);
	  if ($len > $limit) {
	    if (count($suffixes) == 1) {
	      $r[] = $prefix . $suffixes[0];
	    } else {
	      $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
	    }
	    $suffixes = array();
	    $len = $prefix_len + strlen($s);
	  }
	  $suffixes[] = $s;
	}

	if (!empty($suffixes)) {
	  if (count($suffixes) == 1) {
	    $r[] = $prefix . $suffixes[0];
	  } else {
	    $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
	  }
	}
	
	return implode("\n", $r);
}

function optMergePrefixes_Old($m)
{
	$prefix = $m[1];
	$prefix_len = strlen($prefix);

	$suffixes = array();
	foreach (explode("\n", $m[0]) as $line) {
	  $suffixes[] = substr($line, $prefix_len);
	}

	return $prefix . '(?:' . implode('|', $suffixes) . ')';
}

/*
 * Checking errors in pattern
 */
function optSigCheck(&$sigs)
{
	$result = true;

	foreach ($sigs as $k => $sig) {
                if (trim($sig) == "") {
                   if (DEBUG_MODE) {
                      echo("************>>>>> EMPTY\n     pattern: " . $sig . "\n");
                   }
	           unset($sigs[$k]);
		   $result = false;
                }

		if (@preg_match('#' . $sig . '#smiS', '') === false) {
			$error = error_get_last();
                        if (DEBUG_MODE) {
			   echo("************>>>>> " . $error['message'] . "\n     pattern: " . $sig . "\n");
                        }
			unset($sigs[$k]);
			$result = false;
		}
	}
	
	return $result;
}

function _hash_($text)
{
	static $r;
	
	if (empty($r)) {
		for ($i = 0; $i < 256; $i++) {
			if ($i < 33 OR $i > 127 ) $r[chr($i)] = '';
		}
	}

	return sha1(strtr($text, $r));
}

function check_whitelist($list, &$snum) 
{
	if (empty($list)) return array();
	
	$file = dirname(__FILE__) . '/AIBOLIT-WHITELIST.db';

	$snum = max(0, @filesize($file) - 1024) / 20;
	stdOut("\nLoaded " . ceil($snum) . " known files\n");
	
	sort($list);

	$hash = reset($list);
	
	$fp = @fopen($file, 'rb');
	
	if (false === $fp) return array();
	
	$header = unpack('V256', fread($fp, 1024));
	
	$result = array();
	
	foreach ($header as $chunk_id => $chunk_size) {
		if ($chunk_size > 0) {
			$str = fread($fp, $chunk_size);
			
			do {
				$raw = pack("H*", $hash);
				$id = ord($raw[0]) + 1;
				
				if ($chunk_id == $id AND binarySearch($str, $raw)) {
					$result[] = $hash;
				}
				
			} while ($chunk_id >= $id AND $hash = next($list));
			
			if ($hash === false) break;
		}
	}
	
	fclose($fp);

	return $result;
}


function binarySearch($str, $item)
{
	$item_size = strlen($item);	
	if ( $item_size == 0 ) return false;
	
	$first = 0;

	$last = floor(strlen($str) / $item_size);
	
	while ($first < $last) {
		$mid = $first + (($last - $first) >> 1);
		$b = substr($str, $mid * $item_size, $item_size);
		if (strcmp($item, $b) <= 0)
			$last = $mid;
		else
			$first = $mid + 1;
	}

	$b = substr($str, $last * $item_size, $item_size);
	if ($b == $item) {
		return true;
	} else {
		return false;
	}
}

function getSigId($l_Found)
{
	foreach ($l_Found as $key => &$v) {
		if (is_string($key) AND $v[1] != -1 AND strlen($key) == 9) {
			return substr($key, 1);
		}
	}
	
	return null;
}

function die2($str) {
  if (function_exists('aibolit_onFatalError')) { aibolit_onFatalError($str); }
  die($str);
}

function checkFalsePositives($l_Filename, $l_Unwrapped, $l_DeobfType) {
  global $g_DeMapper;

  if ($l_DeobfType != '') {
     if (DEBUG_MODE) {
       stdOut("\n-----------------------------------------------------------------------------\n");
       stdOut("[DEBUG]" . $l_Filename . "\n");
       var_dump(getFragment($l_Unwrapped, $l_Pos));
       stdOut("\n...... $l_DeobfType ...........\n");
       var_dump($l_Unwrapped);
       stdOut("\n");
     }

     switch ($l_DeobfType) {
        case '_GLOBALS_': 
           foreach ($g_DeMapper as $fkey => $fvalue) {
              if (DEBUG_MODE) {
                 stdOut("[$fkey] => [$fvalue]\n");
              }

              if ((strpos($l_Filename, $fkey) !== false) &&
                  (strpos($l_Unwrapped, $fvalue) !== false)) {
                 if (DEBUG_MODE) {
                    stdOut("\n[DEBUG] *** SKIP: False Positive\n");
                 } 

                 return true;
              }
           }
        break;
     }


     return false;
  }
}

$full_code = '';

function deobfuscate_bitrix($str)
{
	$res = $str;
	$funclist = array();
	$strlist = array();
	$res = preg_replace("|[\"']\s*\.\s*['\"]|smi", '', $res);
	$res = preg_replace_callback('~(?:min|max)\(\s*\d+[\,\|\s\|+\|\-\|\*\|\/][\d\s\.\,\+\-\*\/]+\)~ms',"calc",$res);
	$res = preg_replace_callback(
		'|(round\((.+?)\))|smi',
		function ($matches) {
		   return round($matches[2]);
		},
		$res
	);
	$res = preg_replace_callback(
			'|base64_decode\(["\'](.*?)["\']\)|smi',
			function ($matches) {
				return "'" . base64_decode($matches[1]) . "'";
			},
			$res
	);

	$res = preg_replace_callback(
			'|["\'](.*?)["\']|sm',
			function ($matches) {
				$temp = base64_decode($matches[1]);
				if (base64_encode($temp) === $matches[1] && preg_match('#^[ -~]*$#', $temp)) { 
				   return "'" . $temp . "'";
				} else {
				   return "'" . $matches[1] . "'";
				}
			},
			$res
	);	


	if (preg_match_all('|\$GLOBALS\[\'(.+?)\'\]\s*=\s*Array\((.+?)\);|smi', $res, $founds, PREG_SET_ORDER))
	{
		foreach($founds as $found)
		{
			$varname = $found[1];
			$funclist[$varname] = explode(',', $found[2]);
			$funclist[$varname] = array_map(function($value) { return trim($value, "'"); }, $funclist[$varname]);

			$res = preg_replace_callback(
					'|\$GLOBALS\[\'' . $varname . '\'\]\[(\d+)\]|smi',
					function ($matches) use($varname,$funclist){
					   return $funclist[$varname][$matches[1]];
					},
					$res
			);
		}
    }
		

	if (preg_match_all('|function\s*(\w{1,60})\(\$\w+\){\$\w{1,60}\s*=\s*Array\((.{1,30000}?)\);[^}]+}|smi', $res, $founds, PREG_SET_ORDER)) {
		foreach($founds as $found)
		{
			$strlist = explode(',', $found[2]);
			$res = preg_replace_callback(
					'|' . $found[1] . '\((\d+)\)|smi',
					function ($matches) use($strlist){
					   return $strlist[$matches[1]];
					},
					$res
			);

			//$res = preg_replace('~' . quotemeta(str_replace('~', '\\~', $found[0])) . '~smi', '', $res);
		}
    }

  	$res = preg_replace('~<\?(php)?\s*\?>~smi', '', $res);
	if (preg_match_all('~<\?\s*function\s*(_+(.{1,60}?))\(\$[_0-9]+\)\{\s*static\s*\$([_0-9]+)\s*=\s*(true|false);.{1,30000}?\$\3=array\((.*?)\);\s*return\s*base64_decode\(\$\3~smi', $res, $founds,PREG_SET_ORDER)) 
	{
		foreach($founds as $found)
		{
			$strlist = explode("',",$found[5]);
			$res = preg_replace_callback(
					'|' . $found[1] . '\((\d+)\)|sm',
					function ($matches) use($strlist){
					   return $strlist[$matches[1]]."'";
					},
					$res
			);
					
		}
	}
	
	return $res;
}

function calc($expr)
{
	if (is_array($expr)) $expr = $expr[0];
	preg_match('~(min|max)?\(([^\)]+)\)~msi',$expr,$expr_arr);
	if ($expr_arr[1] == 'min' || $expr_arr[1] == 'max') return $expr_arr[1](explode(',',$expr_arr[2]));	
	else
	{
		preg_match_all('~([\d\.]+)([\*\/\-\+])?~',$expr,$expr_arr);
		if (in_array('*',$expr_arr[2])!==false)
		{
			$pos = array_search('*',$expr_arr[2]);
			$res = $expr_arr[1][$pos] * $expr_arr[1][$pos+1];
			$expr = str_replace($expr_arr[1][$pos]."*".$expr_arr[1][$pos+1],$res,$expr);
			$expr = calc($expr);
		}
		elseif (in_array('/',$expr_arr[2])!==false)
		{
			$pos = array_search('/',$expr_arr[2]);
			$res = $expr_arr[1][$pos] / $expr_arr[1][$pos+1];
			$expr = str_replace($expr_arr[1][$pos]."/".$expr_arr[1][$pos+1],$res,$expr);
			$expr = calc($expr);
		}
		elseif (in_array('-',$expr_arr[2])!==false)
		{
			$pos = array_search('-',$expr_arr[2]);
			$res = $expr_arr[1][$pos] - $expr_arr[1][$pos+1];
			$expr = str_replace($expr_arr[1][$pos]."-".$expr_arr[1][$pos+1],$res,$expr);
			$expr = calc($expr);
		}
		elseif (in_array('+',$expr_arr[2])!==false)
		{
			$pos = array_search('+',$expr_arr[2]);
			$res = $expr_arr[1][$pos] + $expr_arr[1][$pos+1];
			$expr = str_replace($expr_arr[1][$pos]."+".$expr_arr[1][$pos+1],$res,$expr);
			$expr = calc($expr);
		}
		else
		{
			return $expr;
		}

		return $expr;
	}
}

function my_eval($matches)
{
    $string = $matches[0];
    $string = substr($string, 5, strlen($string) - 7);
    return decode($string);
}

function decode($string, $level = 0)
{
    if (trim($string) == '') return '';
    if ($level > 100) return '';

    if (($string[0] == '\'') || ($string[0] == '"')) {
        return substr($string, 1, strlen($string) - 2); //
	} elseif ($string[0] == '$') {
		global $full_code;
		$string = str_replace(")","",$string);
		preg_match_all('~\\'.$string.'\s*=\s*(\'|")([^"\']+)(\'|")~msi',$full_code,$matches);
        return $matches[2][0]; //
    } else {
        $pos      = strpos($string, '(');
        $function = substr($string, 0, $pos);
		
        $arg      = decode(substr($string, $pos + 1), $level + 1);
    	if (strtolower($function) == 'base64_decode') return @base64_decode($arg);
    	else if (strtolower($function) == 'gzinflate') return @gzinflate($arg);
		else if (strtolower($function) == 'gzuncompress') return @gzuncompress($arg);
    	else if (strtolower($function) == 'strrev')  return @strrev($arg);
    	else if (strtolower($function) == 'str_rot13')  return @str_rot13($arg);
    	else return $arg;
    }    
}
    
function deobfuscate_eval($str)
{
    global $full_code;
    $res = preg_replace_callback('~eval\((base64_decode|gzinflate|strrev|str_rot13|gzuncompress).*?\);~msi', "my_eval", $str);
    return str_replace($str,$res,$full_code);
}

function getEvalCode($string)
{
    preg_match("/eval\((.*?)\);/", $string, $matches);
    return (empty($matches)) ? '' : end($matches);
}

function getTextInsideQuotes($string)
{
    if (preg_match_all('/("(.*?)")/', $string, $matches)) return @end(end($matches));
	elseif (preg_match_all('/(\'(.*?)\')/', $string, $matches)) return @end(end($matches));
	else return '';
}

function deobfuscate_lockit($str)
{    
    $obfPHP        = $str;
    $phpcode       = base64_decode(getTextInsideQuotes(getEvalCode($obfPHP)));
    $hexvalues     = getHexValues($phpcode);
    $tmp_point     = getHexValues($obfPHP);
    $pointer1      = hexdec($tmp_point[0]);
    $pointer2      = hexdec($hexvalues[0]);
    $pointer3      = hexdec($hexvalues[1]);
    $needles       = getNeedles($phpcode);
    $needle        = $needles[count($needles) - 2];
    $before_needle = end($needles);

    
    $phpcode = base64_decode(strtr(substr($obfPHP, $pointer2 + $pointer3, $pointer1), $needle, $before_needle));
    return "<?php {$phpcode} ?>";
}


function getNeedles($string)
{
    preg_match_all("/'(.*?)'/", $string, $matches);
    
    return (empty($matches)) ? array() : $matches[1];
}

function getHexValues($string)
{
    preg_match_all('/0x[a-fA-F0-9]{1,8}/', $string, $matches);
    return (empty($matches)) ? array() : $matches[0];
}

function deobfuscate_als($str)
{
	preg_match('~__FILE__;\$[O0]+=[0-9a-fx]+;eval\(\$[O0]+\(\'([^\']+)\'\)\);return;~msi',$str,$layer1);
	preg_match('~\$[O0]+=(\$[O0]+\()+\$[O0]+,[0-9a-fx]+\),\'([^\']+)\',\'([^\']+)\'\)\);eval\(~msi',base64_decode($layer1[1]),$layer2);
    $res = explode("?>", $str);
	if (strlen(end($res))>0)
	{
		$res = substr(end($res), 380);
		$res = base64_decode(strtr($res, $layer2[2], $layer2[3]));
	}
    return "<?php {$res} ?>";
}

function deobfuscate_byterun($str)
{
	global $full_code;
	preg_match('~\$_F=__FILE__;\$_X=\'([^\']+)\';\s*eval\s*\(\s*\$?\w{1,60}\s*\(\s*[\'"][^\'"]+[\'"]\s*\)\s*\)\s*;~msi',$str,$matches);
	$res = base64_decode($matches[1]);
	$res = strtr($res,'123456aouie','aouie123456');
    return "<?php " . str_replace($matches[0],$res,$full_code)." ?>";
}

function deobfuscate_urldecode($str)
{
	preg_match('~(\$[O0_]+)=urldecode\("([%0-9a-f]+)"\);((\$[O0_]+=(\1\{\d+\}\.?)+;)+)~msi',$str,$matches);
	$alph = urldecode($matches[2]);
	$funcs=$matches[3];
	for($i = 0; $i < strlen($alph); $i++)
	{
		$funcs = str_replace($matches[1].'{'.$i.'}.',$alph[$i],$funcs);
		$funcs = str_replace($matches[1].'{'.$i.'}',$alph[$i],$funcs);
	}

	$str = str_replace($matches[3], $funcs, $str);
	$funcs = explode(';', $funcs);
	foreach($funcs as $func)
	{
		$func_arr = explode("=", $func);
		if (count($func_arr) == 2)
		{
			$func_arr[0] = str_replace('$', '', $func_arr[0]);
			$str = str_replace('${"GLOBALS"}["' . $func_arr[0] . '"]', $func_arr[1], $str);
		}			
	}

	return $str;
}


function formatPHP($string)
{
    $string = str_replace('<?php', '', $string);
    $string = str_replace('?>', '', $string);
    $string = str_replace(PHP_EOL, "", $string);
    $string = str_replace(";", ";\n", $string);
    return $string;
}

function deobfuscate_fopo($str)
{
    $phpcode = formatPHP($str);
    $phpcode = base64_decode(getTextInsideQuotes(getEvalCode($phpcode)));
    @$phpcode = gzinflate(base64_decode(str_rot13(getTextInsideQuotes(end(explode(':', $phpcode))))));
    $old = '';
    while (($old != $phpcode) && (strlen(strstr($phpcode, '@eval($')) > 0)) {
        $old = $phpcode;
        $funcs = explode(';', $phpcode);
		if (count($funcs) == 5) $phpcode = gzinflate(base64_decode(str_rot13(getTextInsideQuotes(getEvalCode($phpcode)))));
		else if (count($funcs) == 4) $phpcode = gzinflate(base64_decode(getTextInsideQuotes(getEvalCode($phpcode))));
    }
    
    return substr($phpcode, 2);
}

function getObfuscateType($str)
{
    if (preg_match('~\$GLOBALS\[\s*[\'"]_+\w{1,60}[\'"]\s*\]\s*=\s*\s*array\s*\(\s*base64_decode\s*\(~msi', $str))
        return "_GLOBALS_";
    if (preg_match('~function\s*_+\d+\s*\(\s*\$i\s*\)\s*{\s*\$a\s*=\s*Array~msi', $str))
        return "_GLOBALS_";
    if (preg_match('~__FILE__;\$[O0]+=[0-9a-fx]+;eval\(\$[O0]+\(\'([^\']+)\'\)\);return;~msi', $str))
        return "ALS-Fullsite";
    if (preg_match('~\$[O0]*=urldecode\(\'%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64\'\);\s*\$GLOBALS\[\'[O0]*\'\]=\$[O0]*~msi', $str))
        return "LockIt!";
    if (preg_match('~\$\w+="(\\\x?[0-9a-f]+){13}";@eval\(\$\w+\(~msi', $str))
        return "FOPO";
	if (preg_match('~\$_F=__FILE__;\$_X=\'([^\']+\');eval\(~ms', $str))
        return "ByteRun";
    if (preg_match('~(\$[O0_]+)=urldecode\("([%0-9a-f]+)"\);((\$[O0_]+=(\1\{\d+\}\.?)+;)+)~msi', $str))
        return "urldecode_globals";
	if (preg_match('~eval\((base64_decode|gzinflate|strrev|str_rot13|gzuncompress)~msi', $str))
        return "eval";	
}

function deobfuscate($str)
{
    switch (getObfuscateType($str)) {
        case '_GLOBALS_':
            $str = deobfuscate_bitrix(($str));
            break;
        case 'eval':
            $str = deobfuscate_eval(($str));
            break;
        case 'ALS-Fullsite':
            $str = deobfuscate_als(($str));
            break;
        case 'LockIt!':
            $str = deobfuscate_lockit($str);
            break;
        case 'FOPO':
            $str = deobfuscate_fopo(($str));
            break;
	case 'ByteRun':
            $str = deobfuscate_byterun(($str));
            break;
	case 'urldecode_globals' :
            $str = deobfuscate_urldecode(($str));
			break;
    }
    
    return $str;
}
