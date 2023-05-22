<?php
header('Content-Type: text/html; charset=UTF-8');
if ($_SERVER['REQUEST_METHOD'] == 'GET') {
  $messages = array();
  if (!empty($_COOKIE['save'])) {
    setcookie('save', '', 100000);
    setcookie('login', '', 100000);
    setcookie('pass', '', 100000);
    $messages[] = 'Спасибо, результаты сохранены.';
    if (!empty($_COOKIE['pass'])) {
      $messages[] = sprintf('Вы можете <a href="login.php">войти</a> с логином <strong>%s</strong>
          и паролем <strong>%s</strong> для изменения данных.',
        strip_tags($_COOKIE['login']),
        strip_tags($_COOKIE['pass']));
      }
    }
  // Складываем признак ошибок в массив.
  $errors = array();
  $errors['fio'] = !empty($_COOKIE['fio_error']);
  $errors['email'] = !empty($_COOKIE['email_error']);
  $errors['year'] = !empty($_COOKIE['year_error']);
  $errors['gender'] = !empty($_COOKIE['gender_error']);
  $errors['limbs'] = !empty($_COOKIE['limbs_error']);
  $errors['ability'] = !empty($_COOKIE['ability_error']);
  $errors['biography'] = !empty($_COOKIE['biography_error']);

  // Выдаем сообщения об ошибках.
  if ($errors['fio']) {
    // Удаляем куку, указывая время устаревания в прошлом.
    setcookie('fio_error', '', 100000);
    // Выводим сообщение.
    $messages[] = '<div class="error">Заполните имя. Допустимые символы: A-Z, a-z, А-Я, а-я, " " .</div>';}
  if ($errors['email']) {
    setcookie('email_error', '', 100000);
    $messages[] = '<div class="error">Заполните email. Пример: "example@example.ex".</div>';}
  if ($errors['year']) {
    setcookie('year_error', '', 100000);
    $messages[] = '<div class="error">Заполните год. Выберете одно поле из списка.</div>';}
  if ($errors['gender']) {
    setcookie('gender_error', '', 100000);
    $messages[] = '<div class="error">Заполните пол. Выберете одно из допустимых значений: "ж","м".</div>';}
  if ($errors['limbs']) {
    setcookie('limbs_error', '', 100000);
    $messages[] = '<div class="error">Заполните количество конечностей. Выберете одно из допустимых значений: "1","2","3","4".</div>';}
  if ($errors['ability']) {
    setcookie('ability_error', '', 100000);
    $messages[] = '<div class="error">Заполните сверхспособности. Выберете одно или несколько полей из списка.</div>';}
  if ($errors['biography']) {
    setcookie('biography_error', '', 100000);
    $messages[] = '<div class="error">Заполните биографию. Допустимые значения: 0-9, A-Z, a-z, А-Я, а-я, " ", ".", пробельные символы.</div>';}
 
  // Складываем предыдущие значения полей в массив, если есть.
  $values = array();
  $values['fio'] = empty($_COOKIE['fio_value']) ? '' : strip_tags($_COOKIE['fio_value']);
  $values['email'] = empty($_COOKIE['email_value']) ? '' : strip_tags($_COOKIE['email_value']);
  $values['year'] = empty($_COOKIE['year_value']) ? '' : strip_tags($_COOKIE['year_value']);
  $values['gender'] = empty($_COOKIE['gender_value']) ? '' : strip_tags($_COOKIE['gender_value']);
  $values['limbs'] = empty($_COOKIE['limbs_value']) ? '' : strip_tags($_COOKIE['limbs_value']);
  $values['ability'] = empty($_COOKIE['ability_value']) ? array() : json_decode($_COOKIE['ability_value']);
  $values['biography'] = empty($_COOKIE['biography_value']) ? '' : strip_tags($_COOKIE['biography_value']);

  // Если нет предыдущих ошибок ввода, есть кука сессии, начали сессию и
  // ранее в сессию записан факт успешного логина.
  if (empty($errors) && !empty($_COOKIE[session_name()]) &&
      session_start() && !empty($_SESSION['login'])) {
    $user = 'u52992';
    $pass = '5447200';
    $db = new PDO('mysql:host=localhost;dbname=u52992', $user, $pass, array(PDO::ATTR_PERSISTENT => true));
    try{
      $stmt=$db->prepare("SELECT id  FROM user WHERE login=?");
      $stmt->bindParam(1,$_SESSION['login']);
      $stmt->execute();
      $arr=$stmt->fetchAll();

      $stmt=$db->prepare("SELECT * FROM application WHERE user_id=?");
      $stmt->bindParam(1,$arr[0]['id']);
      $stmt->execute();
      $arr1=$stmt->fetchALL();
      $values['fio']=$arr1[0]['name'];
      $values['email']=$arr1[0]['email'];
      $values['year']=$arr1[0]['year'];
      $values['gender']=$arr1[0]['gender'];
      $values['limbs']=$arr1[0]['limbs'];
      $values['biography']=$arr1[0]['biography'];

      $stmt=$db->prepare("SELECT id FROM application WHERE user_id=?");
      $stmt->bindParam(1,$arr[0]['id']);
      $stmt->execute();
      $arr3=$stmt->fetchAll();

      $stmt=$db->prepare("SELECT ability_id FROM ability_application WHERE application_id=?");
      $stmt->bindParam(1,$arr3[0]['id']);
      $stmt->json_encode(execute());
      $values['ability']=$stmt->json_decode();
    }
    catch(PDOException $e){
      print('Error: '.$e->getMessage());
      exit();
    }

    printf('Вход с логином %s, uid %d', $_SESSION['login'], $_SESSION['uid']);
  }


  // Включаем содержимое файла form.php.
  // В нем будут доступны переменные $messages, $errors и $values для вывода 
  // сообщений, полей с ранее заполненными данными и признаками ошибок.
  include('form.php');
  // Завершаем работу скрипта.
  exit();
}

// Иначе, если запрос был методом POST, т.е. нужно проверить данные и сохранить их в XML-файл.
else{
  // Проверяем ошибки.
  $errors = FALSE;
  if (empty($_POST['fio']) || !preg_match('/^([a-zA-Zа-яА-Я\s]{1,})$/', $_POST['fio'])) {
    // Выдаем куку на день с флажком об ошибке в поле fio.
    setcookie('fio_error', '1', time() + 24 * 60 * 60);
    $errors = TRUE;}
  else {
  // Сохраняем ранее введенное в форму значение на месяц.
  setcookie('fio_value', $_POST['fio'], time() + 30 * 24 * 60 * 60); }
  if (empty($_POST['year']) || !is_numeric($_POST['year']) || !preg_match('/^\d+$/', $_POST['year'])) {
    setcookie('year_error', '1', time() + 24 * 60 * 60);
    $errors = TRUE;}
  else {
  setcookie('year_value', $_POST['year'], time() + 30 * 24 * 60 * 60);}
  if (empty($_POST['email']) || !preg_match('/^((([0-9A-Za-z]{1}[-0-9A-z\.]{1,}[0-9A-Za-z]{1})|([0-9А-Яа-я]{1}[-0-9А-я\.]{1,}[0-9А-Яа-я]{1}))@([-A-Za-z]{1,}\.){1,2}[-A-Za-z]{2,})$/u',$_POST['email'])) {
    setcookie('email_error', '1', time() + 24 * 60 * 60);
    $errors = TRUE;}
  else {
    setcookie('email_value', $_POST['email'], time() + 30 * 24 * 60 * 60);}
  if (empty($_POST['gender']) || ($_POST['gender']!='m' && $_POST['gender']!='w')) {
    setcookie('gender_error', '1', time() + 24 * 60 * 60);
    $errors = TRUE;}
  else {
    setcookie('gender_value', $_POST['gender'], time() + 30 * 24 * 60 * 60);}
  if (empty($_POST['limbs']) || ($_POST['limbs']!='1' && $_POST['limbs']!='2' && $_POST['limbs']!='3' && $_POST['limbs']!='4')) {
    setcookie('limbs_error', '1', time() + 24 * 60 * 60);
    $errors = TRUE;}
  else {
    setcookie('limbs_value', $_POST['limbs'], time() + 30 * 24 * 60 * 60);}

  if (empty($_POST['biography']) || !preg_match('/^([0-9a-zA-Zа-яА-Я\,\.\s]{1,})$/', $_POST['biography']) ){
    setcookie('biography_error', '1', time() + 24 * 60 * 60);
    $errors = TRUE;}
  else {
    setcookie('biography_value', $_POST['biography'], time() + 30 * 24 * 60 * 60);}
  foreach ($_POST['ability'] as $ability) {
    if($ability != '1' && $ability != '2' && $ability != '3' && $ability != '4'){
      setcookie('ability_error', '1', time() + 24 * 60 * 60);
      $errors = TRUE;
      break;}}
  if (!empty($_POST['ability'])) {
    setcookie('ability_value', json_encode($_POST['ability']), time() + 24 * 60 * 60);}


  if ($errors) {
    // При наличии ошибок перезагружаем страницу и завершаем работу скрипта.
    header('Location: index.php');
    exit();
  }
  else {
    // Удаляем Cookies с признаками ошибок.
    setcookie('fio_error', '', 100000);
    setcookie('year_error', '', 100000);
    setcookie('email_error', '', 100000);
    setcookie('gender_error', '', 100000);
    setcookie('limbs_error', '', 100000);
    setcookie('biography_error', '', 100000);
    setcookie('ability_error', '', 100000);
  }

  $user = 'u52992';
	$pass = '5447200';	
    $db = new PDO('mysql:host=localhost;dbname=u52992', $user, $pass, array(PDO::ATTR_PERSISTENT => true));
  // Проверяем меняются ли ранее сохраненные данные или отправляются новые.
  if (!empty($_COOKIE[session_name()]) &&
  session_start() && !empty($_SESSION['login'])) {
    // TODO: перезаписать данные в БД новыми данными,
    // кроме логина и пароля.
    $id=$_SESSION['uid'];
    $upd=$db->prepare("UPDATE application SET name=?, email=?, year=?, gender=?, biography=?, limbs=? WHERE user_id=$id");
    $upd->execute([$_POST['fio'], $_POST['email'],$_POST['year'],$_POST['gender'], $_POST['biography'],$_POST['limbs']]);
    
    $stmt=$db->prepare("SELECT id FROM application WHERE user_id=$id");
    $stmt->execute();
    $app_id=$stmt->fetchAll();

    $del=$db->prepare("DELETE FROM ability_application WHERE application_id=?");
    $del->bindParam(1,$app_id[0]['id']);
    $del->execute();

    $stmt = $db->prepare("INSERT INTO ability_application SET ability_id= ?, application_id=?");
    foreach ($_POST['ability'] as $ability) {
      $stmt->execute([$ability, $app_id[0]['id']]);
    }
  }
  else {
  // Генерируем уникальный логин и пароль.
  // TODO: сделать механизм генерации, например функциями rand(), uniquid(), md5(), substr().
  $login = 'u'.substr(uniqid(),-5);
  $pass = substr(md5(uniqid()),0,10);
  $pass_hash=password_hash($pass,PASSWORD_DEFAULT);
  setcookie('login', $login);
  setcookie('pass', $pass);
  try {
    $stmt=$db->prepare("INSERT INTO user SET login=?,pass=?");
    $stmt->bindParam(1,$login);
    $stmt->bindParam(2,$pass_hash);
    $stmt->execute();
    $user_id=$db->lastInsertId();

    $stmt = $db->prepare("INSERT INTO application SET name = ?, email=?, year=?, gender=?, biography=?, limbs=?, user_id=?");
    $stmt->execute([$_POST['fio'], $_POST['email'],$_POST['year'],$_POST['gender'], $_POST['biography'],$_POST['limbs'], $user_id]);

    $app_id=$db->lastInsertId();

    $stmt = $db->prepare("INSERT INTO ability_application SET ability_id= ?, application_id=?");
    foreach ($_POST['ability'] as $ability) {
      $stmt->execute([$ability, $app_id]);
    }
  }
  catch(PDOException $e){
  print('Error : ' . $e->getMessage());
  exit();
  }

  }

  // Сохраняем куку с признаком успешного сохранения.
  setcookie('save', '1');

  // Делаем перенаправление.
  header('Location: ./');
}
?>