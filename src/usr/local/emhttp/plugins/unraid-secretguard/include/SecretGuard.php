<?php
class SecretGuard {
    const TEMPLATE_DIR = '/boot/config/plugins/dockerMan/templates-user';
    const CFG_DIR = '/boot/config/plugins/unraid-secretguard';
    const DEFAULT_SECRET_DIR = '/mnt/cache/appdata/secrets';
    const RUN_DIR = '/run/unraid-secretguard';
    const RUNTIME_ENV_DIR = '/run/unraid-secretguard/env';
    const MASTER_KEY_FILE = '/run/unraid-secretguard/master.key';
    const VAULT_META_FILE = '/boot/config/plugins/unraid-secretguard/vault.json';
    const UNLOCK_STATE_FILE = '/run/unraid-secretguard/unlock-state.json';
    const VAULT_START_FILE = '/boot/config/plugins/unraid-secretguard/vault-start.json';
    const VAULT_VERIFIER_TEXT = 'Unraid SecretGuard Vault Verifier v2';
    const MANAGED_SHARE_NAME = 'secretguard';
    const SHARE_CFG_DIR = '/boot/config/shares';

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
        $status = [
            'exists'=>is_dir($path),'mounted'=>false,'persistent'=>false,'encrypted_hint'=>false,
            'source'=>'unknown','filesystem'=>'unknown','mountpoint'=>'unknown',
            'resolved_path'=>$path,'pool'=>'','state'=>'unknown','details'=>'Encryption not confirmed'
        ];
        $probe = is_dir($path) ? $path : dirname($path);
        while ($probe !== '/' && !is_dir($probe)) $probe = dirname($probe);

        // A direct Unraid pool path such as /mnt/cache/... is a bind-mounted
        // directory below /mnt. findmnt -T therefore often reports rootfs[/mnt],
        // which is not the backing block device. Identify the pool first and
        // inspect Unraid's own mount table for /mnt/<pool>.
        if (preg_match('#^/mnt/([^/]+)(?:/(.*))?$#', $probe, $pm)) {
            $candidatePool=$pm[1];
            if(!in_array($candidatePool,['user','user0','disks','remotes','addons'],true)) {
                $status['pool']=$candidatePool;
            }
        }

        // /mnt/user is FUSE. Resolve it only if exactly one concrete pool/disk
        // contains the requested existing path; otherwise do not claim encryption.
        if (preg_match('#^/mnt/user/(.+)$#', $probe, $m)) {
            $relative=$m[1]; $candidates=[];
            foreach(glob('/mnt/*',GLOB_ONLYDIR)?:[] as $root) {
                $base=basename($root);
                if(in_array($base,['user','user0','disks','remotes','addons'],true)) continue;
                $candidate=$root.'/'.$relative;
                if(file_exists($candidate)) $candidates[]=$candidate;
            }
            if(count($candidates)===1) {
                $probe=$candidates[0];
                if(preg_match('#^/mnt/([^/]+)#',$probe,$pm)) $status['pool']=$pm[1];
            } elseif(count($candidates)>1) {
                $status['details']='User share spans multiple backing locations; encryption cannot be confirmed for every file.';
                return $status;
            }
        }
        $status['resolved_path']=$probe;

        // First try the exact pool mount from /proc/mounts. This bypasses the
        // rootfs[/mnt] bind-mount result returned by findmnt -T on Unraid.
        if($status['pool']!=='') {
            $poolMount='/mnt/'.$status['pool'];
            $mounts=@file('/proc/mounts',FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES)?:[];
            foreach($mounts as $line) {
                $parts=preg_split('/\\s+/',$line);
                if(count($parts)<3) continue;
                $target=str_replace('\\040',' ',$parts[1]);
                if($target===$poolMount) {
                    $status['source']=str_replace('\\040',' ',$parts[0]);
                    $status['filesystem']=$parts[2];
                    $status['mountpoint']=$target;
                    $status['mounted']=true;
                    break;
                }
            }
        }

        if(!$status['mounted']) {
            $line=trim((string)@shell_exec('findmnt -T '.escapeshellarg($probe).' -n -o SOURCE,FSTYPE,TARGET 2>/dev/null'));
            if($line!=='') {
                $parts=preg_split('/\\s+/', $line, 3);
                $status['source']=$parts[0]??'unknown';
                $status['filesystem']=$parts[1]??'unknown';
                $status['mountpoint']=$parts[2]??'unknown';
                $status['mounted']=true;
            }
        }

        // Classify whether the selected path is actually backed by persistent
        // storage. A directory below /mnt is not sufficient: when a pool such
        // as /mnt/cache is absent, the directory can resolve to Unraid rootfs/tmpfs.
        $fsLower=strtolower((string)$status['filesystem']);
        $srcLower=strtolower((string)$status['source']);
        if(in_array($fsLower,['rootfs','tmpfs','ramfs'],true) || strpos($srcLower,'rootfs')===0) {
            $status['persistent']=false;
            $status['state']='not_persistent';
            $status['details']='Configured path resolves to Unraid RAM/rootfs, not persistent storage.';
            return $status;
        }
        if($status['mounted'] && $status['mountpoint']!=='unknown' && preg_match('#^/mnt/(disk[0-9]+|[^/]+)$#',$status['mountpoint'])) {
            $status['persistent']=true;
            $status['state']='persistent';
        }

        // Unraid encrypted array/pool devices are normally mounted through a
        // /dev/mapper/* device. Confirm that directly when present.
        $source=$status['source'];
        if($source!=='unknown' && (preg_match('#^/dev/mapper/#',$source) || preg_match('/crypt/i',$source))) {
            $status['encrypted_hint']=true;
            $status['persistent']=true;
            $status['state']='encrypted';
            $status['details']='Encrypted mapper/device detected';
            return $status;
        }

        // Resolve symlinks such as /dev/disk/by-* before walking the block stack.
        $realSource=($source!=='unknown')?@realpath($source):false;
        if($realSource) $source=$realSource;
        if($source!=='unknown' && preg_match('#^/dev/#',$source)) {
            $pk=trim((string)@shell_exec('lsblk -s -n -o NAME,TYPE '.escapeshellarg($source).' 2>/dev/null'));
            if($pk!=='' && preg_match('/(^|\\s)crypt($|\\s)/m',$pk)) {
                $status['encrypted_hint']=true;
                $status['persistent']=true;
                $status['state']='encrypted';
                $status['details']='Encrypted block-device layer detected';
                return $status;
            }
        }

        // Last Unraid-specific check: map the pool mountpoint through findmnt
        // itself rather than the child directory. Never treat rootfs as proof.
        if($status['pool']!=='') {
            $poolMount='/mnt/'.$status['pool'];
            $poolSource=trim((string)@shell_exec('findmnt -M '.escapeshellarg($poolMount).' -n -o SOURCE 2>/dev/null'));
            if($poolSource!=='' && strpos($poolSource,'rootfs')!==0) {
                $status['source']=$poolSource;
                if(preg_match('#^/dev/mapper/#',$poolSource) || preg_match('/crypt/i',$poolSource)) {
                    $status['encrypted_hint']=true;
                    $status['persistent']=true;
                    $status['state']='encrypted';
                    $status['details']='Encrypted pool mapper detected';
                    return $status;
                }
                $real=@realpath($poolSource); if($real) $poolSource=$real;
                $pk=trim((string)@shell_exec('lsblk -s -n -o NAME,TYPE '.escapeshellarg($poolSource).' 2>/dev/null'));
                if($pk!=='' && preg_match('/(^|\\s)crypt($|\\s)/m',$pk)) {
                    $status['encrypted_hint']=true;
                    $status['persistent']=true;
                    $status['state']='encrypted';
                    $status['details']='Encrypted pool block-device layer detected';
                    return $status;
                }
            }
        }
        return $status;
    }


    public static function storageChoices() {
        $choices=[];
        foreach(glob('/mnt/*',GLOB_ONLYDIR)?:[] as $root) {
            $name=basename($root);
            if(in_array($name,['user','user0','disks','remotes','addons'],true)) continue;
            // Only expose real persistent mounts. This deliberately excludes
            // placeholder directories such as an unmounted /mnt/cache.
            $st=self::storageStatus($root);
            if(!$st['persistent']) continue;
            $choices[]=[
                'name'=>$name,
                'root'=>$root,
                'filesystem'=>$st['filesystem'],
                'encrypted'=>$st['encrypted_hint'],
                'source'=>$st['source']
            ];
        }
        // Always expose cache as the conventional Unraid choice, even when
        // it is currently not mounted. It remains explicitly unsafe/non-
        // persistent until storageStatus() can prove that /mnt/cache is backed
        // by persistent storage.
        $hasCache=false;
        foreach($choices as $c) if($c['name']==='cache') {$hasCache=true;break;}
        if(!$hasCache) {
            $cacheStatus=self::storageStatus('/mnt/cache');
            array_unshift($choices,[
                'name'=>'cache',
                'root'=>'/mnt/cache',
                'filesystem'=>$cacheStatus['filesystem'],
                'encrypted'=>$cacheStatus['encrypted_hint'],
                'persistent'=>$cacheStatus['persistent'],
                'source'=>$cacheStatus['source']
            ]);
        }
        foreach($choices as &$c) {
            if(!array_key_exists('persistent',$c)) $c['persistent']=true;
        }
        unset($c);
        usort($choices,function($a,$b){
            if($a['name']==='cache') return -1;
            if($b['name']==='cache') return 1;
            if($a['encrypted']!==$b['encrypted']) return $a['encrypted']?-1:1;
            return strnatcasecmp($a['name'],$b['name']);
        });
        return $choices;
    }

    public static function recommendedSecretDir() {
        $choices=self::storageChoices();
        if(!$choices) return '';
        foreach($choices as $c) if($c['name']==='cache' && !empty($c['persistent'])) return $c['root'].'/appdata/secrets';
        foreach($choices as $c) if(!empty($c['persistent']) && $c['encrypted']) return $c['root'].'/appdata/secrets';
        foreach($choices as $c) if(!empty($c['persistent'])) return $c['root'].'/appdata/secrets';
        return '';
    }

    public static function assertPlainStorageSafe($secretDir) {
        $st=self::storageStatus($secretDir);
        if(!$st['persistent']) {
            throw new Exception('Plain env migration blocked: the secret directory is not backed by persistent storage (rootfs/tmpfs/RAM or an unmounted pool). Choose a mounted disk/pool or use Vault.');
        }
    }

    public static function managedShareStatus() {
        $result=['exists'=>false,'managed'=>false,'path'=>'','storage'=>'','encrypted'=>false,'config'=>''];
        foreach(self::storageChoices() as $choice) {
            if(empty($choice['persistent'])) continue;
            $path=rtrim($choice['root'],'/').'/'.self::MANAGED_SHARE_NAME;
            $marker=$path.'/.secretguard-managed';
            if(is_dir($path)) {
                $result['exists']=true;
                $result['path']=$path;
                $result['storage']=$choice['name'];
                $result['encrypted']=!empty($choice['encrypted']);
                $result['managed']=is_file($marker);
                break;
            }
        }
        $cfg=self::SHARE_CFG_DIR.'/'.self::MANAGED_SHARE_NAME.'.cfg';
        if(is_file($cfg)) $result['config']=$cfg;
        return $result;
    }

    public static function createManagedShare($storageRoot) {
        $storageRoot=rtrim(trim((string)$storageRoot),'/');
        $allowed=null;
        foreach(self::storageChoices() as $choice) {
            if(($choice['root']??'')===$storageRoot && !empty($choice['persistent'])) {$allowed=$choice;break;}
        }
        if(!$allowed) throw new Exception('Choose a mounted persistent storage device/pool.');
        $status=self::storageStatus($storageRoot);
        if(empty($status['persistent'])) throw new Exception('Selected storage is not persistent.');

        $shareName=self::MANAGED_SHARE_NAME;
        $sharePath=$storageRoot.'/'.$shareName;
        $marker=$sharePath.'/.secretguard-managed';
        $cfg=self::SHARE_CFG_DIR.'/'.$shareName.'.cfg';

        if(is_dir($sharePath) && !is_file($marker)) {
            $entries=array_values(array_diff(scandir($sharePath)?:[],['.','..']));
            if($entries) throw new Exception('A non-SecretGuard directory already exists at '.$sharePath.'. Refusing to take ownership of it.');
        }
        if(is_file($cfg) && !is_file($marker)) {
            throw new Exception('An existing Unraid share configuration named "'.$shareName.'" already exists. SecretGuard will not overwrite it.');
        }

        if(!is_dir($sharePath) && !mkdir($sharePath,0700,true)) throw new Exception('Unable to create '.$sharePath.'.');
        chmod($sharePath,0700);
        $markerData=['managed_by'=>'Unraid SecretGuard','version'=>1,'storage_root'=>$storageRoot,'created'=>gmdate('c')];
        if(file_put_contents($marker,json_encode($markerData,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n",LOCK_EX)===false) throw new Exception('Unable to create SecretGuard share marker.');
        chmod($marker,0600);

        if(!is_dir(self::SHARE_CFG_DIR) && !mkdir(self::SHARE_CFG_DIR,0700,true)) throw new Exception('Unable to create Unraid share config directory.');
        $name=(string)$allowed['name'];
        $isDisk=(bool)preg_match('/^disk[0-9]+$/',$name);
        $cfgLines=[
            '# Generated settings:',
            'shareComment="SecretGuard protected credential storage"',
            'shareInclude="'.($isDisk?$name:'').'"',
            'shareExclude=""',
            'shareUseCache="'.($isDisk?'no':'only').'"',
            'shareCachePool="'.($isDisk?'cache':addcslashes($name,'\\"')).'"',
            'shareCOW="auto"',
            'shareAllocator="highwater"',
            'shareSplitLevel=""',
            'shareFloor="0"',
            'shareExport="-"',
            'shareCaseSensitive="auto"',
            'shareSecurity="private"',
            'shareReadList=""',
            'shareWriteList=""',
            'shareVolsizelimit=""',
            'shareExportNFS="-"',
            'shareExportNFSFsid="0"',
            'shareSecurityNFS="private"',
            'shareHostListNFS=""'
        ];
        $tmp=$cfg.'.tmp.'.getmypid();
        if(file_put_contents($tmp,implode("\n",$cfgLines)."\n",LOCK_EX)===false) throw new Exception('Unable to stage Unraid share configuration.');
        chmod($tmp,0600);
        if(!rename($tmp,$cfg)) throw new Exception('Unable to activate Unraid share configuration.');
        chmod($cfg,0600);
        return ['path'=>$sharePath,'storage'=>$name,'encrypted'=>!empty($allowed['encrypted']),'config'=>$cfg];
    }

    public static function cryptoStatus() {
        $security = self::unlockSecurityStatus();
        return [
            'sodium' => function_exists('sodium_crypto_pwhash') && function_exists('sodium_crypto_secretbox'),
            'openssl' => function_exists('openssl_encrypt') && function_exists('openssl_decrypt'),
            'initialized' => is_file(self::VAULT_META_FILE),
            'unlocked' => is_file(self::MASTER_KEY_FILE),
            'failed_attempts' => $security['failures'],
            'cooldown_remaining' => $security['cooldown_remaining'],
            'last_failed' => $security['last_failed'],
            'last_source' => $security['last_source'],
        ];
    }

    public static function initializeVault($password, $confirm) {
        if ($password !== $confirm) throw new Exception('Master passwords do not match.');
        self::validateMasterPassword($password);
        if (is_file(self::VAULT_META_FILE)) throw new Exception('Vault is already initialized. Unlock it instead.');
        self::ensureCfgDir();
        self::ensureRunDir();
        $meta = self::newVaultMeta();
        $key = self::deriveKey($password, $meta);
        $meta['verifier_blob'] = self::encryptBlobWithKey(self::VAULT_VERIFIER_TEXT, $key);
        if (!self::writeVaultMeta($meta)) throw new Exception('Unable to write vault metadata.');
        self::writeMasterKey($key);
        self::clearUnlockLockout();
        return $meta['kdf'];
    }

    public static function unlockVault($password, $secretDir, $source='unknown') {
        self::assertUnlockAllowed();
        $meta = self::loadVaultMeta();
        $key = self::deriveKey($password, $meta);
        if (!self::verifyDerivedKey($key, $meta)) {
            $state = self::recordUnlockFailure($source);
            throw new Exception('Incorrect vault master password. Next attempt allowed in '.$state['cooldown_remaining'].' second(s).');
        }
        self::clearUnlockLockout();

        // Transparently upgrade legacy HMAC verifier metadata after a successful unlock.
        if (empty($meta['verifier_blob'])) {
            $meta['version'] = 2;
            $meta['verifier_blob'] = self::encryptBlobWithKey(self::VAULT_VERIFIER_TEXT, $key);
            unset($meta['verifier']);
            self::writeVaultMeta($meta);
        }

        self::writeMasterKey($key);
        $count = self::restoreRuntimeEnvs($secretDir);
        $resume = self::resumeVaultContainers($secretDir);
        return ['env_count'=>$count,'resumed'=>$resume['resumed'],'errors'=>$resume['errors']];
    }

    public static function lockVault($secretDir) {
        $stopped = self::stopVaultContainers($secretDir, true);
        if (!empty($stopped['errors'])) {
            throw new Exception('Vault lock aborted because one or more protected containers could not be stopped: '.implode('; ', $stopped['errors']));
        }
        self::removeRuntimeVaultMaterial();
        return ['stopped'=>$stopped['stopped']];
    }

    public static function enforceLockedVault($secretDir) {
        if (!is_file(self::VAULT_META_FILE) || is_file(self::MASTER_KEY_FILE)) return ['stopped'=>[],'errors'=>[]];
        return self::stopVaultContainers($secretDir, true);
    }

    public static function changeMasterPassword($oldPassword, $newPassword, $confirm, $secretDir, $source='unknown') {
        if ($newPassword !== $confirm) throw new Exception('New master passwords do not match.');
        self::validateMasterPassword($newPassword);
        self::assertUnlockAllowed();

        $oldMeta = self::loadVaultMeta();
        $oldKey = self::deriveKey($oldPassword, $oldMeta);
        if (!self::verifyDerivedKey($oldKey, $oldMeta)) {
            $state = self::recordUnlockFailure($source);
            throw new Exception('Current vault master password is incorrect. Next attempt allowed in '.$state['cooldown_remaining'].' second(s).');
        }
        self::clearUnlockLockout();

        if (!self::validSecretDir($secretDir)) throw new Exception('Invalid secret directory.');
        $vaultFiles = glob(rtrim($secretDir,'/').'/*.sgv') ?: [];
        $plaintext = [];
        foreach ($vaultFiles as $file) {
            $blob = json_decode((string)file_get_contents($file), true);
            if (!is_array($blob)) throw new Exception('Invalid encrypted vault file: '.basename($file));
            $plaintext[$file] = self::decryptBlobWithKey($blob, $oldKey);
        }

        $newMeta = self::newVaultMeta();
        $newKey = self::deriveKey($newPassword, $newMeta);
        $newMeta['verifier_blob'] = self::encryptBlobWithKey(self::VAULT_VERIFIER_TEXT, $newKey);

        $staged = []; $oldCopies = []; $metaTmp = self::VAULT_META_FILE.'.rekey-new.'.getmypid();
        try {
            foreach ($plaintext as $file=>$plain) {
                $oldBlob = json_decode((string)file_get_contents($file), true);
                $purpose = is_array($oldBlob) ? ($oldBlob['purpose'] ?? 'env') : 'env';
                $blob = self::encryptBlobWithKey($plain, $newKey);
                $blob['purpose'] = $purpose;
                $blob['created'] = gmdate('c');
                $tmp = $file.'.rekey-new.'.getmypid();
                if (file_put_contents($tmp, json_encode($blob,JSON_UNESCAPED_SLASHES)."\n", LOCK_EX) === false) throw new Exception('Unable to stage re-encrypted vault file.');
                chmod($tmp,0600);
                $check = json_decode((string)file_get_contents($tmp), true);
                if (!is_array($check) || !hash_equals($plain, self::decryptBlobWithKey($check, $newKey))) throw new Exception('Re-encrypted vault verification failed for '.basename($file).'.');
                $staged[$file] = $tmp;
            }

            if (file_put_contents($metaTmp, json_encode($newMeta,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n", LOCK_EX) === false) throw new Exception('Unable to stage new vault metadata.');
            chmod($metaTmp,0600);

            foreach ($staged as $file=>$tmp) {
                $old = $file.'.rekey-old.'.getmypid();
                if (!rename($file,$old)) throw new Exception('Unable to stage old vault file for atomic replacement.');
                $oldCopies[$file] = $old;
                if (!rename($tmp,$file)) throw new Exception('Unable to replace vault file during rekey.');
                chmod($file,0600);
            }

            if (!rename($metaTmp,self::VAULT_META_FILE)) throw new Exception('Unable to activate new vault metadata.');
            chmod(self::VAULT_META_FILE,0600);
            foreach ($oldCopies as $old) @unlink($old);

            self::writeMasterKey($newKey);
            self::restoreRuntimeEnvs($secretDir);
            self::securityLog('Vault master password changed successfully.', $source);
            return count($vaultFiles);
        } catch (Throwable $e) {
            // Restore old encrypted files if activation failed at any point.
            foreach ($oldCopies as $file=>$old) {
                if (is_file($old)) {
                    @unlink($file);
                    @rename($old,$file);
                }
            }
            foreach ($staged as $tmp) if (is_file($tmp)) @unlink($tmp);
            if (is_file($metaTmp)) @unlink($metaTmp);
            self::writeMasterKey($oldKey);
            throw $e;
        }
    }

    public static function vaultResetStatus($secretDir) {
        if(!self::validSecretDir($secretDir)) return ['safe'=>false,'protected'=>[],'vault_files'=>[]];
        $protected=self::protectedVaultContainers($secretDir);
        $vaultFiles=glob(rtrim($secretDir,'/').'/*.sgv')?:[];
        return ['safe'=>empty($protected)&&empty($vaultFiles),'protected'=>$protected,'vault_files'=>$vaultFiles];
    }

    public static function resetVault($secretDir) {
        $status=self::vaultResetStatus($secretDir);
        if(!empty($status['protected'])) throw new Exception('Vault reset refused: '.count($status['protected']).' container(s) still use Vault mode. Roll them back or migrate them to plain env files first.');
        if(!empty($status['vault_files'])) throw new Exception('Vault reset refused: encrypted .sgv files still exist in the configured secret directory. Roll back/migrate those secrets first so no credentials are destroyed.');
        self::removeRuntimeVaultMaterial();
        foreach([self::VAULT_META_FILE,self::VAULT_START_FILE,self::UNLOCK_STATE_FILE] as $file) if(is_file($file) && !@unlink($file)) throw new Exception('Unable to remove '.basename($file).'.');
        self::securityLog('Vault configuration reset by administrator.');
        return true;
    }

    public static function unlockSecurityStatus() {
        $state = self::loadUnlockState();
        $remaining = max(0, (int)($state['lockout_until'] ?? 0) - time());
        return [
            'failures'=>(int)($state['failures'] ?? 0),
            'cooldown_remaining'=>$remaining,
            'last_failed'=>(string)($state['last_failed'] ?? ''),
            'last_source'=>(string)($state['last_source'] ?? ''),
        ];
    }

    public static function clearUnlockLockout() {
        if (is_file(self::UNLOCK_STATE_FILE)) @unlink(self::UNLOCK_STATE_FILE);
    }

    private static function assertUnlockAllowed() {
        $state = self::unlockSecurityStatus();
        if ($state['cooldown_remaining'] > 0) {
            throw new Exception('Vault unlock is temporarily rate-limited. Try again in '.$state['cooldown_remaining'].' second(s).');
        }
    }

    private static function recordUnlockFailure($source) {
        self::ensureRunDir();
        $state = self::loadUnlockState();
        $failures = (int)($state['failures'] ?? 0) + 1;
        if ($failures <= 3) $delay = 2;
        elseif ($failures <= 5) $delay = 10;
        elseif ($failures <= 10) $delay = 60;
        else $delay = 900;
        $state = [
            'failures'=>$failures,
            'lockout_until'=>time()+$delay,
            'last_failed'=>gmdate('c'),
            'last_source'=>(string)$source,
        ];
        file_put_contents(self::UNLOCK_STATE_FILE,json_encode($state,JSON_UNESCAPED_SLASHES)."\n",LOCK_EX);
        chmod(self::UNLOCK_STATE_FILE,0600);
        self::securityLog('Failed Vault unlock attempt #'.$failures.' from '.$source.'. Cooldown '.$delay.'s.', $source);
        if (in_array($failures,[3,6,10,11],true) || ($failures>11 && $failures%5===0)) {
            self::notifySecurity('Repeated Vault unlock failures', 'SecretGuard detected '.$failures.' failed Vault unlock attempts. Last source: '.$source.'. Current cooldown: '.$delay.' seconds.');
        }
        return self::unlockSecurityStatus();
    }

    private static function loadUnlockState() {
        if (!is_file(self::UNLOCK_STATE_FILE)) return [];
        $state = json_decode((string)file_get_contents(self::UNLOCK_STATE_FILE),true);
        return is_array($state)?$state:[];
    }

    private static function securityLog($message,$source='') {
        $suffix = $source!=='' ? ' source='.$source : '';
        @exec('/usr/bin/logger -t unraid-secretguard '.escapeshellarg($message.$suffix).' >/dev/null 2>&1');
    }

    private static function notifySecurity($subject,$description) {
        $notify='/usr/local/emhttp/webGui/scripts/notify';
        if (is_executable($notify)) {
            @exec(escapeshellcmd($notify).' -e '.escapeshellarg('Unraid SecretGuard').' -s '.escapeshellarg($subject).' -d '.escapeshellarg($description).' -i warning >/dev/null 2>&1');
        }
    }

    private static function validateMasterPassword($password) {
        if (strlen($password) < 16) throw new Exception('Use a master password of at least 16 characters; 20+ random characters or a long passphrase is recommended.');
    }

    private static function newVaultMeta() {
        $salt = random_bytes(16);
        $meta = ['version'=>2,'salt'=>base64_encode($salt)];
        if (function_exists('sodium_crypto_pwhash')) {
            $meta['kdf'] = 'argon2id';
            $meta['opslimit'] = SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE;
            $meta['memlimit'] = SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE;
        } else {
            $meta['kdf'] = 'pbkdf2-sha256';
            $meta['iterations'] = 600000;
        }
        return $meta;
    }

    private static function writeVaultMeta(array $meta) {
        $tmp=self::VAULT_META_FILE.'.tmp.'.getmypid();
        if (file_put_contents($tmp,json_encode($meta,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n",LOCK_EX)===false) return false;
        chmod($tmp,0600);
        if (!rename($tmp,self::VAULT_META_FILE)) {@unlink($tmp);return false;}
        chmod(self::VAULT_META_FILE,0600);
        return true;
    }

    private static function verifyDerivedKey($key,array $meta) {
        if (!empty($meta['verifier_blob']) && is_array($meta['verifier_blob'])) {
            try {
                $plain = self::decryptBlobWithKey($meta['verifier_blob'],$key);
                return hash_equals(self::VAULT_VERIFIER_TEXT,$plain);
            } catch(Throwable $e) {
                return false;
            }
        }
        // Legacy v1 verifier support.
        if (!empty($meta['verifier'])) {
            $legacy = base64_encode(hash_hmac('sha256','Unraid SecretGuard vault verification v1',$key,true));
            return hash_equals((string)$meta['verifier'],$legacy);
        }
        return false;
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
        return self::encryptBlobWithKey($plaintext,self::readMasterKey());
    }

    private static function encryptBlobWithKey($plaintext,$key) {
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
        return self::decryptBlobWithKey($blob,self::readMasterKey());
    }

    private static function decryptBlobWithKey(array $blob,$key) {
        $nonce = base64_decode($blob['nonce'] ?? '', true);
        $ciphertext = base64_decode($blob['data'] ?? '', true);
        if ($nonce === false || $ciphertext === false) throw new Exception('Encrypted vault data is malformed.');
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

    public static function recreateContainer($container,$forceStart=false) {
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
        if($forceStart) {
            if(!self::containerRunning($container)) @exec('docker start ' . escapeshellarg($container) . ' >/dev/null 2>&1');
        } elseif(!$wasRunning && self::containerRunning($container)) {
            @exec('docker stop ' . escapeshellarg($container) . ' >/dev/null 2>&1');
        }
        return ['ok'=>true,'message'=>'Container recreated automatically using the updated Unraid template.'];
    }

    private static function protectedVaultContainers($secretDir) {
        $names=[];
        foreach(self::containerOverview($secretDir) as $row) {
            if(!empty($row['protected']) && ($row['mode']??'')==='vault') $names[$row['container']]=true;
        }
        return array_keys($names);
    }

    private static function loadVaultStartIntent() {
        if(!is_file(self::VAULT_START_FILE)) return [];
        $data=json_decode((string)file_get_contents(self::VAULT_START_FILE),true);
        if(!is_array($data) || !isset($data['containers']) || !is_array($data['containers'])) return [];
        return array_values(array_unique(array_filter(array_map('strval',$data['containers']))));
    }

    private static function saveVaultStartIntent(array $containers) {
        self::ensureCfgDir();
        $data=['containers'=>array_values(array_unique($containers)),'updated'=>gmdate('c')];
        $tmp=self::VAULT_START_FILE.'.tmp.'.getmypid();
        if(file_put_contents($tmp,json_encode($data,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n",LOCK_EX)===false) throw new Exception('Unable to save Vault container start state.');
        chmod($tmp,0600);
        if(!rename($tmp,self::VAULT_START_FILE)) throw new Exception('Unable to activate Vault container start state.');
        chmod(self::VAULT_START_FILE,0600);
    }

    private static function stopVaultContainers($secretDir,$mergeIntent=true) {
        $protected=self::protectedVaultContainers($secretDir);
        $intent=$mergeIntent?self::loadVaultStartIntent():[];
        $stopped=[];$errors=[];
        foreach($protected as $container) {
            if(!self::containerRunning($container)) continue;
            $out=[];$code=1;
            @exec('docker stop '.escapeshellarg($container).' 2>&1',$out,$code);
            if($code===0) {$stopped[]=$container;$intent[]=$container;}
            else $errors[]=$container.': '.trim(implode(' ',array_slice($out,-3)));
        }
        if($mergeIntent && ($stopped || is_file(self::VAULT_START_FILE))) self::saveVaultStartIntent($intent);
        return ['stopped'=>$stopped,'errors'=>$errors];
    }

    private static function resumeVaultContainers($secretDir) {
        $intent=self::loadVaultStartIntent();
        $protected=array_fill_keys(self::protectedVaultContainers($secretDir),true);
        $resumed=[];$errors=[];
        foreach($intent as $container) {
            if(!isset($protected[$container])) continue;
            $r=self::recreateContainer($container,true);
            if($r['ok']) $resumed[]=$container; else $errors[]=$container.': '.$r['message'];
        }
        if(!$errors && is_file(self::VAULT_START_FILE)) @unlink(self::VAULT_START_FILE);
        return ['resumed'=>$resumed,'errors'=>$errors];
    }

    private static function removeRuntimeVaultMaterial() {
        if (is_file(self::MASTER_KEY_FILE)) @unlink(self::MASTER_KEY_FILE);
        if (is_dir(self::RUNTIME_ENV_DIR)) {
            foreach (glob(self::RUNTIME_ENV_DIR . '/*.env') ?: [] as $f) @unlink($f);
        }
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
        if($mode==='plain') self::assertPlainStorageSafe($secretDir);
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
