<!DOCTYPE html>
<head>
    <meta charset="utf-8" />
    <title>backend3</title>
    <link rel="stylesheet" href="style.css" type="text/css"/>
</head>

<body>
  <div class="main">
  <h1>Форма</h1>
  <?php
              if (!empty($messages)) {
                print('<div id="messages">');
                // Выводим все сообщения.
                foreach ($messages as $message) {
                  print($message);
                }
                print('</div>');
              }

              // Далее выводим форму отмечая элементы с ошибками классом error
              // и задавая начальные значения элементов ранее сохраненными.
             //print_r($values);
            ?>
            <form action="" method="POST">
              <label>Ваше Имя:</label><br>
              <input name="fio" <?php print($errors['fio']? 'class="error"' : '');?> value="<?php print $values['fio']; ?>"/><br>

              <label>Еmail:</label>
              <input name="email" <?php print($errors['email']? 'class="error"':'');?> value="<?php print $values['email']; ?>"/><br>

              <label>Год рождения:</label><br>
              <select name="year" <?php print($errors['year'] ? 'class="error"' : '');?>>
                <?php 
                  for ($i = 1922; $i <= 2022; $i++) {
                    $selected = ($i == $values['year']) ? 'selected="selected"' : '';
                    printf('<option value="%d" %s>%d год</option>', $i, $selected, $i);
                  }
                ?>
              </select><br>

              <label>Пол:</label><br>
              <label><input name="gender" type="radio" value="w" <?php print($errors['gender']? 'class="error"': '');?> 
                        <?php if ($values['gender']=='w') print 'checked';?>/>Женский</label>
              <label><input name="gender" type="radio" value="m" <?php print($errors['gender']? 'class="error"': '');?> 
                        <?php if ($values['gender']=='m') print 'checked';?>/>Мужской</label><br>

              <label>Количество конечностей:</label><br>
              <label>1<input name="limbs" type="radio" value="1" <?php print($errors['limbs']? 'class="error"': '');?> 
                      <?php if ($values['limbs']=='1') print 'checked';?>/></label><br>
              <label>2<input name="limbs" type="radio" value="2" <?php print($errors['limbs']? 'class="error"': '');?> 
                       <?php if ($values['limbs']=='2') print 'checked';?>/></label><br>
              <label>3<input name="limbs" type="radio" value="3" <?php print($errors['limbs']? 'class="error"': '');?> 
                       <?php if ($values['limbs']=='3') print 'checked';?>/></label><br>
              <label>4<input name="limbs" type="radio" value="4"<?php print($errors['limbs']? 'class="error"': '');?> 
                       <?php if ($values['limbs']=='4') print 'checked';?>/></label><br>

              <label>Сверхспособности</label><br>
              <select name="ability[]" multiple="multiple" <?php print($errors['ability']? 'class="error"': '');?>>
                <option value="1" <?php print(in_array('1', $values['ability']) ? 'selected="selected"' : ''); ?>>none</option>
                <option value="2" <?php print(in_array('2', $values['ability']) ? 'selected="selected"' : '');?>>Бессмертие</option>
                <option value="3" <?php print(in_array('3', $values['ability']) ? 'selected="selected"' : ''); ?>>Прохождения сквозь стены</option>
                <option value="4" <?php print(in_array('4', $values['ability']) ? 'selected="selected"' : ''); ?>>Левитация</option>
              </select><br>

              <label>Биография:</label><br>
              <textarea name="biography" type="textarea" <?php print($errors['biography']? 'class="error"': '');?>><?php print $values['biography']; ?></textarea><br>

              <label>Отправить  </label>
              <input type="submit" value="ok" />
            </form>
  </div>
</body>