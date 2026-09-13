<?php
class SecretGuard {
    const TEMPLATE_DIR = '/boot/config/plugins/dockerMan/templates-user';
    const CFG_DIR = '/boot/config/plugins/unraid-secretguard';
    const DEFAULT_SECRET_DIR = '/mnt/cache/appdata/secrets';
    const RUN_DIR = '/run/unraid-secretguard';
    const RUNTIME_ENV_DIR = '/run/unraid-secretguard/env';
    const MASTER_KEY_FILE = '/run/unraid-secretguard/master.key';
    const VAULT_META_FILE = '/boot/config/plugins/unraid-secretguard/vault.json';

    private static $highPatterns = [
        '/(^|_)(PASSWORD|PASSWD|PASS|SECRET|TOKEN|API_KEY|APIKEY|CLIENT_SECRET|ACCESS_TOKEN|REFRESH_TOKEN|PRIVATE_KEY|AUTH_TOKEN)(_|$)/i',
        '/(^|_)(AWS_SECRET_ACCESS_KEY|CF_API_TOKEN|CLOUDFLARE_API_TOKEN)(_|$)/i'
    ];
    private static $mediumPatterns = [
        '/(^|_)(KEY|AUTH|CREDENTIAL|CREDENTIALS|ACCESS_KEY|CLAIM)(_|$)/i'
    ];
    private static $ignorePatterns = [
        '/^(TZ|PUID|PGID|UID|GID|UMASK|HOST|HOSTNAME|PORT|PATH|HOME|LANG|LANGUAGE|TERM|VERSION)$/i',
        '/(_URL|_URI|_HOST|_PORT|_PATH)$/i'
    ];

    public static function settings() {
        $settings = [
            'SECRET_DIR' => self::DEFAULT_SECRET_DIR,
            'STORAGE_MODE' => 'plain',
            'AUTO_WATCH' => 'yes'
        ];
        $file = self::CFG_DIR . '/settings.cfg';
        if (is_file($file)) {
            $parsed = @parse_ini_file($file, false, INI_SCANNER_RAW);
            if (is_array($parsed)) $settings = array_merge($settings, $parsed);
        }
        if (!in_array($settings['STORAGE_MODE'], ['plain','vault'], true)) $settings['STORAGE_MODE'] = 'plain';
        if (!in_array($settings['AUTO_WATCH'], ['yes','no'], true)) $settings['AUTO_WATCH'] = 'yes';
        return $settings;
    }

    public static function saveSettings($secretDir, $mode, $watch) {
        $secretDir = rtrim(trim($secretDir), '/');
        if (!self::validSecretDir($secretDir)) throw new Exception('Secret directory must be an absolute path under /mnt/.');
        if (!in_array($mode, ['plain','vault'], true)) throw new Exception('Invalid storage mode.');
        if (!in_array($watch, ['yes','no'], true)) throw new Exception('Invalid watcher setting.');
        self::ensureCfgDir();
        $content = 'SECRET_DIR="' . addcslashes($secretDir, "\\\"") . '"' . PHP_EOL;
        $content .= 'STORAGE_MODE="' . $mode . '"' . PHP_EOL;
        $content .= 'AUTO_WATCH="' . $watch . '"' . PHP_EOL;
        if (file_put_contents(self::CFG_DIR . '/settings.cfg', $content, LOCK_EX) === false) throw new Exception('Unable to save settings.');
        chmod(self::CFG_DIR . '/settings.cfg', 0600);
    }

    private static function ensureCfgDir() {
        if (!is_dir(self::CFG_DIR) && !mkdir(self::CFG_DIR, 0700, true)) throw new Exception('Unable to create plugin config directory.');
        chmod(self::CFG_DIR, 0700);
    }

    private static function ensureRunDir() {
        if (!is_dir(self::RUN_DIR) && !mkdir(self::RUN_DIR, 0700, true)) throw new Exception('Unable to create SecretGuard runtime directory.');
        chmod(self::RUN_DIR, 0700);
        if (!is_dir(self::RUNTIME_ENV_DIR) && !mkdir(self::RUNTIME_ENV_DIR, 0700, true)) throw new Exception('Unable to create runtime env directory.');
        chmod(self::RUNTIME_ENV_DIR, 0700);
    }

    public static function validSecretDir($path) {
        return is_string($path) && preg_match('#^/mnt/[A-Za-z0-9._/-]+$#', $path) && strpos($path, '..') === false;
    }

    public static function storageStatus($path) {
        $status = ['exists'=>is_dir($path),'mounted'=>false,'encrypted_hint'=>false,'source'=>'unknown'];
        $probe = is_dir($path) ? $path : dirname($path);
        while ($probe !== '/' && !is_dir($probe)) $probe = dirname($probe);
        $source = trim((string)@shell_exec('findmnt -T ' . escapeshellarg($probe) . ' -no SOURCE 2>/dev/null'));
        if ($source !== '') {
            $status['mounted'] = true;
            $status['source'] = $source;
            if (preg_match('#^/dev/mapper/#', $source) || preg_match('/crypt/i', $source)) $status['encrypted_hint'] = true;
        }
        return $status;
    }

    public static function cryptoStatus() {
        return [
            'sodium' => function_exists('sodium_crypto_pwhash') && function_exists('sodium_crypto_secretbox'),
            'openssl' => function_exists('openssl_encrypt') && function_exists('openssl_decrypt'),
            'initialized' => is_file(self::VAULT_META_FILE),
            'unlocked' => is_file(self::MASTER_KEY_FILE),
        ];
    }

    public static function initializeVault($password, $confirm) {
        if ($password !== $confirm) throw new Exception('Master passwords do not match.');
        if (strlen($password) < 12) throw new Exception('Use a master password of at least 12 characters; a long passphrase is recommended.');
        if (is_file(self::VAULT_META_FILE)) throw new Exception('Vault is already initialized. Unlock it instead.');
        self::ensureCfgDir();
        self::ensureRunDir();
        $salt = random_bytes(16);
        $meta = ['version'=>1,'salt'=>base64_encode($salt)];
        if (function_exists('sodium_crypto_pwhash')) {
            $meta['kdf'] = 'argon2id';
            $meta['opslimit'] = SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE;
            $meta['memlimit'] = SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE;
        } else {
            $meta['kdf'] = 'pbkdf2-sha256';
            $meta['iterations'] = 600000;
        }
        $key = self::deriveKey($password, $meta);
        $meta['verifier'] = base64_encode(hash_hmac('sha256', 'Unraid SecretGuard vault verification v1', $key, true));
        if (file_put_contents(self::VAULT_META_FILE, json_encode($meta, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES) . "\n", LOCK_EX) === false) throw new Exception('Unable to write vault metadata.');
        chmod(self::VAULT_META_FILE, 0600);
        self::writeMasterKey($key);
        return $meta['kdf'];
    }

    public static function unlockVault($password, $secretDir) {
        $meta = self::loadVaultMeta();
        $key = self::deriveKey($password, $meta);
        $verifier = base64_encode(hash_hmac('sha256', 'Unraid SecretGuard vault verification v1', $key, true));
        if (!isset($meta['verifier']) || !hash_equals($meta['verifier'], $verifier)) throw new Exception('Incorrect vault master password.');
        self::writeMasterKey($key);
        return self::restoreRuntimeEnvs($secretDir);
    }

    public static function lockVault() {
        if (is_file(self::MASTER_KEY_FILE)) @unlink(self::MASTER_KEY_FILE);
        if (is_dir(self::RUNTIME_ENV_DIR)) {
            foreach (glob(self::RUNTIME_ENV_DIR . '/*.env') ?: [] as $f) @unlink($f);
        }
    }

    private static function writeMasterKey($key) {
        self::ensureRunDir();
        if (file_put_contents(self::MASTER_KEY_FILE, $key, LOCK_EX) === false) throw new Exception('Unable to store runtime vault key.');
        chmod(self::MASTER_KEY_FILE, 0600);
    }

    private static function loadVaultMeta() {
        if (!is_file(self::VAULT_META_FILE)) throw new Exception('Vault has not been initialized.');
        $meta = json_decode((string)file_get_contents(self::VAULT_META_FILE), true);
        if (!is_array($meta) || empty($meta['salt']) || empty($meta['kdf'])) throw new Exception('Vault metadata is invalid.');
        return $meta;
    }

    private static function deriveKey($password, array $meta) {
        $salt = base64_decode($meta['salt'], true);
        if ($salt === false || strlen($salt) !== 16) throw new Exception('Vault salt is invalid.');
        if ($meta['kdf'] === 'argon2id') {
            if (!function_exists('sodium_crypto_pwhash')) throw new Exception('This vault requires PHP sodium/Argon2id, but sodium is unavailable.');
            $ops = (int)($meta['opslimit'] ?? SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE);
            $mem = (int)($meta['memlimit'] ?? SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE);
            return sodium_crypto_pwhash(32, $password, $salt, $ops, $mem, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
        }
        if ($meta['kdf'] === 'pbkdf2-sha256') {
            $iterations = max(300000, (int)($meta['iterations'] ?? 600000));
            return hash_pbkdf2('sha256', $password, $salt, $iterations, 32, true);
        }
        throw new Exception('Unsupported vault KDF.');
    }

    private static function readMasterKey() {
        if (!is_file(self::MASTER_KEY_FILE)) throw new Exception('Vault is locked. Unlock it in SecretGuard before migrating or restoring secrets.');
        $key = file_get_contents(self::MASTER_KEY_FILE);
        if ($key === false || strlen($key) !== 32) throw new Exception('Runtime vault key is invalid.');
        return $key;
    }

    private static function encryptBlob($plaintext) {
        $key = self::readMasterKey();
        if (function_exists('sodium_crypto_secretbox')) {
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);
            return ['version'=>1,'cipher'=>'xsalsa20-poly1305','nonce'=>base64_encode($nonce),'data'=>base64_encode($ciphertext)];
        }
        if (!function_exists('openssl_encrypt')) throw new Exception('Neither PHP sodium nor OpenSSL encryption is available.');
        $nonce = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, '', 16);
        if ($ciphertext === false) throw new Exception('Vault encryption failed.');
        return ['version'=>1,'cipher'=>'aes-256-gcm','nonce'=>base64_encode($nonce),'tag'=>base64_encode($tag),'data'=>base64_encode($ciphertext)];
    }

    private static function decryptBlob(array $blob) {
        $key = self::readMasterKey();
        $nonce = base64_decode($blob['nonce'] ?? '', true);
        $ciphertext = base64_decode($blob['data'] ?? '', true);
        if ($nonce === false || $ciphertext === false) throw new Exception('Encrypted vault file is malformed.');
        if (($blob['cipher'] ?? '') === 'xsalsa20-poly1305') {
            if (!function_exists('sodium_crypto_secretbox_open')) throw new Exception('PHP sodium is required to decrypt this vault.');
            $plain = sodium_crypto_secretbox_open($ciphertext, $nonce, $key);
            if ($plain === false) throw new Exception('Vault authentication failed.');
            return $plain;
        }
        if (($blob['cipher'] ?? '') === 'aes-256-gcm') {
            $tag = base64_decode($blob['tag'] ?? '', true);
            if ($tag === false) throw new Exception('Encrypted vault authentication tag is malformed.');
            $plain = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, '');
            if ($plain === false) throw new Exception('Vault authentication failed.');
            return $plain;
        }
        throw new Exception('Unsupported vault cipher.');
    }

    public static function installedContainerNames() {
        $output = []; $code = 1;
        @exec("docker ps -a --format '{{.Names}}' 2>/dev/null", $output, $code);
        if ($code !== 0) return [];
        $names = [];
        foreach ($output as $name) {
            $name = trim($name);
            if ($name !== '') $names[$name] = true;
        }
        return $names;
    }

    public static function templateContainerName($file) {
        $dom = new DOMDocument();
        if (!is_file($file) || !@$dom->load($file)) return '';
        $xp = new DOMXPath($dom);
        $nameNode = $xp->query('/Container/Name')->item(0);
        return $nameNode ? trim($nameNode->textContent) : '';
    }

    public static function scan() {
        $results = [];
        $installed = self::installedContainerNames();
        if (!$installed) return $results;
        foreach (glob(self::TEMPLATE_DIR . '/*.xml') ?: [] as $file) {
            $container = self::templateContainerName($file);
            if ($container === '' || !isset($installed[$container])) continue;
            $results = array_merge($results, self::scanFile($file));
        }
        usort($results, function($a,$b){
            $rank=['high'=>0,'medium'=>1,'low'=>2,'ignore'=>3];
            $ra=$rank[$a['classification']]??9; $rb=$rank[$b['classification']]??9;
            return $ra===$rb ? strcasecmp($a['container'].$a['target'],$b['container'].$b['target']) : $ra<=>$rb;
        });
        return $results;
    }

    public static function scanFile($file) {
        $results=[]; $dom=new DOMDocument(); $dom->preserveWhiteSpace=false;
        if (!is_file($file) || !@$dom->load($file)) return $results;
        $xp=new DOMXPath($dom); $nameNode=$xp->query('/Container/Name')->item(0);
        $container=$nameNode?trim($nameNode->textContent):basename($file,'.xml');
        foreach ($xp->query('/Container/Config[@Type="Variable"]') as $node) {
            $target=trim($node->getAttribute('Target')); if ($target==='') continue;
            $value=trim($node->textContent); if ($value==='') $value=trim($node->getAttribute('Default'));
            $mask=strtolower($node->getAttribute('Mask'))==='true'; $c=self::classify($target,$mask,$value);
            $results[]=['container'=>$container,'file'=>$file,'target'=>$target,'name'=>$node->getAttribute('Name'),'mask'=>$mask,'has_value'=>$value!=='','classification'=>$c['level'],'reason'=>$c['reason']];
        }
        return $results;
    }

    public static function classify($target,$mask,$value) {
        foreach(self::$ignorePatterns as $p) if(preg_match($p,$target)) return ['level'=>'ignore','reason'=>'Common non-secret configuration'];
        if($mask && $value!=='') return ['level'=>'high','reason'=>'Template marks this value as masked'];
        foreach(self::$highPatterns as $p) if(preg_match($p,$target)) return ['level'=>'high','reason'=>'Variable name strongly indicates a secret'];
        foreach(self::$mediumPatterns as $p) if(preg_match($p,$target)) return ['level'=>'medium','reason'=>'Variable name may contain sensitive credentials'];
        return ['level'=>'low','reason'=>'No strong secret indicator'];
    }

    public static function containerRunning($container) {
        $out=[]; $code=1;
        @exec('docker inspect -f ' . escapeshellarg('{{.State.Running}}') . ' ' . escapeshellarg($container) . ' 2>/dev/null', $out, $code);
        return $code===0 && isset($out[0]) && trim($out[0])==='true';
    }

    public static function recreateContainer($container) {
        $script='/usr/local/emhttp/plugins/dynamix.docker.manager/scripts/update_container';
        if(!is_file($script)) return ['ok'=>false,'message'=>'Unraid update_container helper was not found. Re-apply the container manually in Docker Manager.'];
        $installed=self::installedContainerNames();
        if(!isset($installed[$container])) return ['ok'=>false,'message'=>'Container is no longer installed.'];
        $wasRunning=self::containerRunning($container);
        $out=[]; $code=1;
        @exec('/usr/bin/php -q ' . escapeshellarg($script) . ' ' . escapeshellarg($container) . ' 2>&1', $out, $code);
        if($code!==0) {
            $tail=trim(implode("\n",array_slice($out,-8)));
            return ['ok'=>false,'message'=>'Automatic recreate failed'.($tail!==''?': '.$tail:'.')];
        }
        // Keep a container that was stopped before the transaction stopped afterwards.
        if(!$wasRunning && self::containerRunning($container)) {
            @exec('docker stop ' . escapeshellarg($container) . ' >/dev/null 2>&1');
        }
        return ['ok'=>true,'message'=>'Container recreated automatically using the updated Unraid template.'];
    }

    private static function readSecretBundle($mode,$plain,$vault) {
        $text='';
        if($mode==='plain') {
            if(is_file($plain)) $text=(string)file_get_contents($plain);
        } elseif($mode==='vault') {
            if(is_file($vault)) $text=self::decryptVaultFile($vault);
        }
        return self::parseSecretEnvText($text);
    }

    private static function templateInfo($file,$secretDir) {
        $dom=new DOMDocument();
        if(!is_file($file) || !@$dom->load($file)) return null;
        $xp=new DOMXPath($dom); $nameNode=$xp->query('/Container/Name')->item(0);
        if(!$nameNode) return null;
        $container=trim($nameNode->textContent); $safeName=preg_replace('/[^A-Za-z0-9._-]+/','-',$container);
        $extra=$xp->query('/Container/ExtraParams')->item(0); $extraText=$extra?trim($extra->textContent):'';
        $plain=$secretDir.'/'.$safeName.'.env';
        $runtime=self::RUNTIME_ENV_DIR.'/'.$safeName.'.env';
        $vault=$secretDir.'/'.$safeName.'.sgv';
        $protected=false; $mode=''; $envFile=''; $count=null; $names=[]; $rollbackAvailable=false; $legacy=false;
        if(preg_match('#(?:^|\\s)--env-file=([^\\s]+)#',$extraText,$m)) {
            $candidate=$m[1];
            if($candidate===$plain) {$protected=true;$mode='plain';$envFile=$plain;}
            elseif($candidate===$runtime) {$protected=true;$mode='vault';$envFile=$runtime;}
        }
        if($protected) {
            try {
                if($mode==='plain' && is_file($plain)) $bundle=self::readSecretBundle('plain',$plain,$vault);
                elseif($mode==='vault' && is_file($vault) && is_file(self::MASTER_KEY_FILE)) $bundle=self::readSecretBundle('vault',$plain,$vault);
                else $bundle=null;
                if(is_array($bundle)) {
                    $count=count($bundle['vars']); $names=array_keys($bundle['vars']);
                    $rollbackAvailable=$count>0;
                    foreach($names as $n) if(empty($bundle['meta'][$n])) {$rollbackAvailable=false;$legacy=true;break;}
                }
            } catch(Throwable $e) {$count=null;$names=[];$rollbackAvailable=false;}
        }
        return ['container'=>$container,'file'=>$file,'safe_name'=>$safeName,'protected'=>$protected,'mode'=>$mode,'env_file'=>$envFile,'vault_file'=>$vault,'secret_count'=>$count,'secret_names'=>$names,'rollback_available'=>$rollbackAvailable,'legacy'=>$legacy];
    }

    public static function containerOverview($secretDir) {
        if(!self::validSecretDir($secretDir)) return [];
        $installed=self::installedContainerNames(); if(!$installed) return [];
        $rows=[];
        foreach(glob(self::TEMPLATE_DIR.'/*.xml')?:[] as $file) {
            $info=self::templateInfo($file,$secretDir); if(!$info || !isset($installed[$info['container']])) continue;
            $rows[]=$info;
        }
        usort($rows,function($a,$b){return strcasecmp($a['container'],$b['container']);});
        return $rows;
    }

    public static function rollback($file,$secretDir) {
        $realTemplateDir=realpath(self::TEMPLATE_DIR); $realFile=realpath($file);
        if(!$realFile || dirname($realFile)!==$realTemplateDir) throw new Exception('Invalid template path.');
        if(!self::validSecretDir($secretDir)) throw new Exception('Invalid secret directory.');
        $info=self::templateInfo($realFile,$secretDir); if(!$info) throw new Exception('Unable to read template.');
        if(!$info['protected']) throw new Exception('This container is not protected by SecretGuard.');
        if($info['mode']==='vault') self::readMasterKey();

        $plain=$secretDir.'/'.$info['safe_name'].'.env';
        $vault=$secretDir.'/'.$info['safe_name'].'.sgv';
        $runtime=self::RUNTIME_ENV_DIR.'/'.$info['safe_name'].'.env';
        $bundle=self::readSecretBundle($info['mode'],$plain,$vault);
        if(empty($bundle['vars'])) throw new Exception('SecretGuard env file is empty or unavailable.');
        foreach($bundle['vars'] as $target=>$value) {
            if(empty($bundle['meta'][$target]) || !is_array($bundle['meta'][$target])) {
                throw new Exception('Rollback metadata is missing for '.$target.'. This looks like a legacy SecretGuard migration; rollback was stopped to avoid changing unrelated template settings.');
            }
        }

        $dom=new DOMDocument('1.0','UTF-8'); $dom->preserveWhiteSpace=false; $dom->formatOutput=true;
        if(!@$dom->load($realFile)) throw new Exception('Unable to parse template XML.');
        $xp=new DOMXPath($dom); $containerNode=$xp->query('/Container')->item(0);
        if(!$containerNode) throw new Exception('Template has no Container root.');

        foreach($bundle['vars'] as $target=>$value) {
            $existing=$xp->query('/Container/Config[@Type="Variable" and @Target='.self::xpathLiteral($target).']')->item(0);
            if($existing) throw new Exception($target.' already exists in the XML template; rollback aborted to avoid overwriting it.');
            $meta=$bundle['meta'][$target];
            $config=$dom->createElement('Config');
            foreach(($meta['attrs']??[]) as $k=>$v) $config->setAttribute((string)$k,(string)$v);
            if(!$config->hasAttribute('Target')) $config->setAttribute('Target',$target);
            if(!$config->hasAttribute('Type')) $config->setAttribute('Type','Variable');
            $config->appendChild($dom->createTextNode($value));
            $containerNode->appendChild($config);
        }

        $extra=$xp->query('/Container/ExtraParams')->item(0);
        if($extra) {
            $current=trim($extra->textContent);
            foreach([$plain,$runtime] as $managedPath) {
                $current=preg_replace('#(?:^|\\s)--env-file='.preg_quote($managedPath,'#').'(?=\\s|$)#',' ',$current);
            }
            $extra->nodeValue=trim(preg_replace('/\\s+/',' ',$current));
        }

        $tmp=$realFile.'.secretguard.tmp'; if($dom->save($tmp)===false) throw new Exception('Unable to write rolled-back XML.');
        chmod($tmp,0600); if(!rename($tmp,$realFile)) throw new Exception('Unable to replace template XML.');
        foreach([$plain,$vault,$runtime] as $f) if(is_file($f)) @unlink($f);
        $recreate=self::recreateContainer($info['container']);
        return ['container'=>$info['container'],'restored'=>array_keys($bundle['vars']),'recreate'=>$recreate];
    }

    public static function migrate($file,array $targets,$secretDir,$mode='plain') {
        $realTemplateDir=realpath(self::TEMPLATE_DIR); $realFile=realpath($file);
        if(!$realFile || dirname($realFile)!==$realTemplateDir) throw new Exception('Invalid template path.');
        if(!self::validSecretDir($secretDir)) throw new Exception('Invalid secret directory.');
        if(!$targets) throw new Exception('No variables selected.');
        if(!in_array($mode,['plain','vault'],true)) throw new Exception('Invalid storage mode.');
        if(!is_dir($secretDir) && !mkdir($secretDir,0700,true)) throw new Exception('Could not create secret directory.');
        chmod($secretDir,0700);
        if($mode==='vault') self::readMasterKey();

        $dom=new DOMDocument('1.0','UTF-8'); $dom->preserveWhiteSpace=false; $dom->formatOutput=true;
        if(!@$dom->load($realFile)) throw new Exception('Unable to parse template XML.');
        $xp=new DOMXPath($dom); $nameNode=$xp->query('/Container/Name')->item(0);
        if(!$nameNode) throw new Exception('Template has no container name.');
        $container=trim($nameNode->textContent); $safeName=preg_replace('/[^A-Za-z0-9._-]+/','-',$container);
        $plain=$secretDir.'/'.$safeName.'.env'; $vaultFile=$secretDir.'/'.$safeName.'.sgv';

        if($mode==='vault') {
            $bundle=is_file($vaultFile)?self::readSecretBundle('vault',$plain,$vaultFile):['vars'=>[],'meta'=>[]];
            $envFile=self::RUNTIME_ENV_DIR.'/'.$safeName.'.env';
        } else {
            $bundle=is_file($plain)?self::readSecretBundle('plain',$plain,$vaultFile):['vars'=>[],'meta'=>[]];
            $envFile=$plain; $vaultFile=null;
        }
        $existing=$bundle['vars']; $metadata=$bundle['meta'];

        $migrated=[]; $targetSet=array_fill_keys($targets,true);
        foreach(iterator_to_array($xp->query('/Container/Config[@Type="Variable"]')) as $node){
            $target=trim($node->getAttribute('Target')); if(!isset($targetSet[$target])) continue;
            $value=(string)$node->textContent; if($value==='') $value=(string)$node->getAttribute('Default');
            if($value==='') throw new Exception($target.' has no value; refusing to migrate an empty secret.');
            if(preg_match('/[\\r\\n]/',$value)) throw new Exception($target.' contains a newline and cannot be safely migrated as an env value.');
            $attrs=[]; foreach($node->attributes as $attr) $attrs[$attr->nodeName]=$attr->nodeValue;
            $description=$node->getAttribute('Description');
            $metadata[$target]=['attrs'=>$attrs,'description'=>$description];
            $existing[$target]=$value; $migrated[]=$target; $node->parentNode->removeChild($node);
        }
        if(!$migrated) throw new Exception('None of the selected variables were found in this template.');

        $envText=self::renderSecretEnv($existing,$metadata);
        if($mode==='vault') {
            self::ensureRunDir(); self::writeEncryptedFile($secretDir.'/'.$safeName.'.sgv',$envText,'env'); self::writeTextFile($envFile,$envText,0600);
        } else self::writeTextFile($envFile,$envText,0600);

        $extra=$xp->query('/Container/ExtraParams')->item(0);
        if(!$extra){$extra=$dom->createElement('ExtraParams');$xp->query('/Container')->item(0)->appendChild($extra);}
        $arg='--env-file='.$envFile; $current=trim($extra->textContent);
        foreach([$plain,self::RUNTIME_ENV_DIR.'/'.$safeName.'.env'] as $managedPath) {
            $current=preg_replace('#(?:^|\\s)--env-file='.preg_quote($managedPath,'#').'(?=\\s|$)#',' ',$current);
        }
        $extra->nodeValue=trim(preg_replace('/\\s+/',' ',trim($current.' '.$arg)));

        $tmp=$realFile.'.secretguard.tmp'; if($dom->save($tmp)===false) throw new Exception('Unable to write updated XML.');
        chmod($tmp,0600); if(!rename($tmp,$realFile)) throw new Exception('Unable to replace template XML.');
        $recreate=self::recreateContainer($container);
        return ['container'=>$container,'env_file'=>$envFile,'vault_file'=>$vaultFile,'migrated'=>$migrated,'mode'=>$mode,'recreate'=>$recreate];
    }

    public static function restoreRuntimeEnvs($secretDir) {
        if(!self::validSecretDir($secretDir)) throw new Exception('Invalid secret directory.');
        self::ensureRunDir(); $count=0;
        foreach(glob(rtrim($secretDir,'/').'/*.sgv')?:[] as $vaultFile){
            $blob=json_decode((string)file_get_contents($vaultFile),true);
            if(!is_array($blob) || ($blob['purpose']??'')!=='env') continue;
            $plain=self::decryptBlob($blob); $name=basename($vaultFile,'.sgv');
            self::writeTextFile(self::RUNTIME_ENV_DIR.'/'.$name.'.env',$plain,0600); $count++;
        }
        return $count;
    }

    private static function decryptVaultFile($file) {
        $blob=json_decode((string)file_get_contents($file),true); if(!is_array($blob)) throw new Exception('Invalid encrypted vault file: '.basename($file));
        return self::decryptBlob($blob);
    }

    private static function writeEncryptedFile($file,$plaintext,$purpose) {
        $blob=self::encryptBlob($plaintext); $blob['purpose']=$purpose; $blob['created']=gmdate('c');
        $tmp=$file.'.tmp.'.getmypid();
        if(file_put_contents($tmp,json_encode($blob,JSON_UNESCAPED_SLASHES)."\n",LOCK_EX)===false) throw new Exception('Unable to write encrypted file.');
        chmod($tmp,0600); if(!rename($tmp,$file)) throw new Exception('Unable to replace encrypted file.'); chmod($file,0600);
    }

    private static function xpathLiteral($value) {
        if(strpos($value,"'")===false) return "'".$value."'";
        if(strpos($value,'"')===false) return '"'.$value.'"';
        $parts=explode("'",$value); $chunks=[];
        foreach($parts as $i=>$part){if($part!=='')$chunks[]="'".$part."'";if($i<count($parts)-1)$chunks[]='"\\\'"';}
        return 'concat('.implode(',',$chunks).')';
    }
    public static function parseEnvFile($file){return is_file($file)?self::parseEnvText((string)file_get_contents($file)):[];}
    public static function parseEnvText($text){return self::parseSecretEnvText($text)['vars'];}
    public static function parseSecretEnvText($text){
        $vars=[];$meta=[];$pending=null;
        foreach(preg_split('/\r?\n/',$text) as $line){
            $trim=ltrim($line); if($trim==='') continue;
            if(strpos($trim,'# SecretGuard-Meta: ')===0){
                $raw=base64_decode(trim(substr($trim,20)),true); $decoded=$raw!==false?json_decode($raw,true):null;
                $pending=is_array($decoded)?$decoded:null; continue;
            }
            if($trim[0]==='#') continue;
            $p=strpos($line,'='); if($p===false) continue;
            $name=substr($line,0,$p); $vars[$name]=substr($line,$p+1);
            if(is_array($pending) && (($pending['target']??$name)===$name)) $meta[$name]=$pending;
            $pending=null;
        }
        return ['vars'=>$vars,'meta'=>$meta];
    }
    public static function renderEnv(array $vars){return self::renderSecretEnv($vars,[]);}
    public static function renderSecretEnv(array $vars,array $meta){
        ksort($vars,SORT_NATURAL|SORT_FLAG_CASE);$out='';
        foreach($vars as $k=>$v){
            if(!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/',$k))throw new Exception('Invalid environment variable name: '.$k);
            if(preg_match('/[\r\n]/',$v))throw new Exception('Multiline values are not supported.');
            if(isset($meta[$k])&&is_array($meta[$k])){
                $m=$meta[$k];$m['target']=$k;
                $desc=trim((string)($m['description']??''));
                $out.='# SecretGuard protected variable: '.$k."\n";
                if($desc!=='') $out.='# Description: '.str_replace(["\r","\n"],' ',$desc)."\n";
                $json=json_encode($m,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
                $out.='# SecretGuard-Meta: '.base64_encode($json)."\n";
            }
            $out.=$k.'='.$v."\n\n";
        }
        return rtrim($out)."\n";
    }
    private static function writeTextFile($file,$text,$mode){$dir=dirname($file);if(!is_dir($dir)&&!mkdir($dir,0700,true))throw new Exception('Unable to create directory: '.$dir);$tmp=$file.'.tmp.'.getmypid();if(file_put_contents($tmp,$text,LOCK_EX)===false)throw new Exception('Unable to write file.');chmod($tmp,$mode);if(!rename($tmp,$file))throw new Exception('Unable to replace file.');chmod($file,$mode);}
}
