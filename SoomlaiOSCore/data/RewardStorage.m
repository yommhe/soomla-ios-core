/*
 Copyright (C) 2012-2014 Soomla Inc.
 
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

#import "RewardStorage.h"
#import "Reward.h"
#import "SequenceReward.h"
#import "SoomlaEventHandling.h"
#import "KeyValueStorage.h"
#import "SoomlaConfig.h"
#import "SoomlaUtils.h"

@implementation RewardStorage


+ (void)setStatus:(BOOL)status forReward:(Reward *)reward {
    [self setStatus:status forReward:reward andNotify:YES];
}

+ (void)setStatus:(BOOL)status forReward:(Reward *)reward andNotify:(BOOL)notify {
    [self setTimesGivenForReward:reward up:status andNotify:notify];
}

+ (BOOL)isRewardGiven:(Reward *)reward {
    return [self getTimesGivenForReward:reward] > 0;
}

+ (int)getLastSeqIdxGivenForReward:(SequenceReward *)sequenceReward {
    NSString* key = [self keyRewardIdxSeqGivenWithRewardId:sequenceReward.ID];
    NSString* val = [KeyValueStorage getValueForKey:key];
    
    if (!val || [val length] == 0){
        return -1;
    }
    
    return [val intValue];
}

+ (void)setLastSeqIdxGiven:(int)idx ForReward:(SequenceReward *)sequenceReward {
    NSString* key = [self keyRewardIdxSeqGivenWithRewardId:sequenceReward.ID];
    NSString* val = [[NSNumber numberWithInt:idx] stringValue];
    
    [KeyValueStorage setValue:val forKey:key];
}

+ (void)setTimesGivenForReward:(Reward*)reward up:(BOOL)up andNotify:(BOOL)notify {
    int total = [self getTimesGivenForReward:reward] + (up ? 1 : -1);
    NSString* key = [self keyRewardTimesGiven:reward.ID];
    NSString* val = [[NSNumber numberWithInt:total] stringValue];
    
    [KeyValueStorage setValue:val forKey:key];
    
    if (up) {
        key = [self keyRewardLastGiven:reward.ID];
        val = [NSString stringWithFormat:@"%lld",(long long)([[NSDate date] timeIntervalSince1970] * 1000)];
        
        [KeyValueStorage setValue:val forKey:key];
    }
    
    if (notify) {
        if (up) {
            [SoomlaEventHandling postRewardGiven:reward];
        } else {
            [SoomlaEventHandling postRewardTaken:reward];
        }
    }
}

+ (int)getTimesGivenForReward:(Reward*)reward {
    NSString* key = [self keyRewardTimesGiven:reward.ID];
    NSString* val = [KeyValueStorage getValueForKey:key];
    if (!val || [val length] == 0){
        return 0;
    }
    return [val intValue];
}

+ (NSDate*)getLastGivenTimeForReward:(Reward*)reward {
    long long timeMillis = [self getLastGivenTimeMillisForReward:reward];
    if (timeMillis == 0) {
        return NULL;
    }
    return [NSDate dateWithTimeIntervalSince1970:(timeMillis/1000)];
}

+ (long long)getLastGivenTimeMillisForReward:(Reward*)reward {
    NSString* key = [self keyRewardTimesGiven:reward.ID];
    NSString* val = [KeyValueStorage getValueForKey:key];
    if (!val || [val length] == 0){
        return 0;
    }
    return [val longLongValue];
}


// Private

+ (NSString *)keyRewardsWithRewardId:(NSString *)rewardId AndPostfix:(NSString *)postfix {
    return [NSString stringWithFormat: @"%@rewards.%@.%@", DB_KEY_PREFIX, rewardId, postfix];
}

+ (NSString *)keyRewardTimesGiven:(NSString *)rewardId {
    return [self keyRewardsWithRewardId:rewardId AndPostfix:@"timesGiven"];
}

+ (NSString *)keyRewardLastGiven:(NSString *)rewardId {
    return [self keyRewardsWithRewardId:rewardId AndPostfix:@"lastGiven"];
}

+ (NSString *)keyRewardIdxSeqGivenWithRewardId:(NSString *)rewardId {
    return [self keyRewardsWithRewardId:rewardId AndPostfix:@"seq.idx"];
}

@end
