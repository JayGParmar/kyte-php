<?php

namespace Kyte\Mvc\Controller;

class SiteController extends ModelController
{
    // public function hook_init() {}
    // public function hook_auth() {}

    // public function hook_prequery($method, &$field, &$value, &$conditions, &$all, &$order) {}

    // public function hook_preprocess($method, &$r, &$o = null) {}

    public function hook_response_data($method, $o, &$r = null, &$d = null) {
        switch ($method) {
            case 'new':
                $app = new \Kyte\Core\ModelObject(Application);
                if (!$app->retrieve('id', $d['application'])) {
                    throw new \Exception("CRITICAL ERROR: Unable to find application.");
                    $o->delete();
                }

                // get AWS credentials
                $region = 'us-east-1';
                $credentials = new \Kyte\Aws\Credentials($region);

                // create s3 bucket for site data
                $bucketName = strtolower(preg_replace('/[^A-Za-z0-9_.-]/', '-', $r['name']).'-'.$app->identifier);
                $o->save([
                    'region'        => $region,
                    's3BucketName'  => $bucketName,
                ]);
                $s3 = new \Kyte\Aws\S3($credentials, $bucketName, 'public-read');
                try {
                    $s3->createBucket();
                } catch(\Exception $e) {
                    throw $e;
                    $o->delete();
                }
                
                $s3->createWebsite();
                $s3->enablePublicAccess();

                // create s3 bucket for static media assets
                $mediaBucketName = strtolower(preg_replace('/[^A-Za-z0-9_-]/', '-', $r['name']).'-static-assets-'.$app->identifier);
                $o->save([
                    's3MediaBucketName'  => $mediaBucketName,
                ]);
                $s3 = new \Kyte\Aws\S3($credentials, $mediaBucketName, 'public-read');
                try {
                    $s3->createBucket();
                } catch(\Exception $e) {
                    throw $e;
                    $o->delete();
                }
                
                $s3->enablePublicAccess();
                // enable cors for upload
                $s3->enableCors([
                    [
                        'AllowedHeaders'    =>  ['*'],
                        'AllowedMethods'    =>  ['GET','POST'],
                        'AllowedOrigins'    =>  ['*'],
                    ]
                ]);

                // create distribution for website
                $cf = new \Kyte\Aws\CloudFront($credentials);
                $cf->addOrigin(
                    $bucketName.'.s3-website-'.$region.'.amazonaws.com',
                    $bucketName
                );
                $cf->create();
                $o->save([
                    'cfDistributionId'        => $cf->Id,
                    'cfDomain'                => $cf->domainName,
                ]);

                // create distribution for static assets
                $cf = new \Kyte\Aws\CloudFront($credentials);
                $cf->addOrigin(
                    $mediaBucketName.'.s3.amazonaws.com',
                    $mediaBucketName
                );
                $cf->create();
                $o->save([
                    'cfMediaDistributionId'        => $cf->Id,
                    'cfMediaDomain'                => $cf->domainName,
                ]);

                // update return data
                $r['region'] = $region;
                $r['s3BucketName'] = $bucketName;
                $r['cfDistributionId'] = $cf->Id;
                $r['cfDomain'] = $cf->domainName;

                break;
            case 'delete':
                // // get AWS credentials
                // $credentials = new \Kyte\Aws\Credentials('us-east-1');

                // // disable distribution
                // $cf = new \Kyte\Aws\CloudFront($credentials, $o->cfDistribution);
                // $cf->disable();

                // delete distribution
                // $cf->delete();

                // // delete acm certificate
                // $acm = new \Kyte\Aws\Acm($credentials, $o->AcmArn);
                // $acm->delete();

                // delete s3 bucket
                // $s3 = new \Kyte\Aws\S3($credentials, $o->s3bucket, 'public');
                // $s3->emptyBucket(); <- create method
                // $s3->deleteBucket();

                break;
            
            default:
                break;
        }
    }

    // public function hook_process_get_response(&$r) {}
}
