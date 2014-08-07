//
//  TimeStrategy.h
//  SoomlaiOSCore
//
//  Created by Refael Dakar on 06/08/14.
//  Copyright (c) 2014 SOOMLA. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, Strategy) {
    EVERYMONTH,
    EVERYDAY,
    EVERYHOUR,
    CUSTOM,
    ALWAYS
};

@interface TimeStrategy : NSObject {
    Strategy strategy;
    NSDate*  startTime;
    int      repeatTimes;
}

@property (nonatomic, readonly) Strategy strategy;
@property (nonatomic, retain, readonly) NSDate*  startTime;
@property (nonatomic, readonly) int      repeatTimes;


+ (TimeStrategy*)Once;
+ (TimeStrategy*)OnceWithStartTime:(NSDate*)oStartTime;
+ (TimeStrategy*)EveryMonthWithStartTime:(NSDate*)oStartTime andRepeatTimes:(int)oRepeatTimes;
+ (TimeStrategy*)EveryDayWithStartTime:(NSDate*)oStartTime andRepeatTimes:(int)oRepeatTimes;
+ (TimeStrategy*)EveryHourWithStartTime:(NSDate*)oStartTime andRepeatTimes:(int)oRepeatTimes;
+ (TimeStrategy*)CustomWithRepeatTimes:(int)oRepeatTimes;
+ (TimeStrategy*)CustomWithStartTime:(NSDate*)oStartTime andRepeatTimes:(int)oRepeatTimes;
+ (TimeStrategy*)Always;
+ (TimeStrategy*)AlwaysWithStartTime:(NSDate*)oStartTime;


- (id)initWithDictionary:(NSDictionary *)dict;
- (NSDictionary *)toDictionary;
- (BOOL)approveWithLastTime:(NSDate*)lastTime andTimesApproved:(int)timesApproved;

@end
